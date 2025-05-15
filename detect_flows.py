#!/usr/bin/env python3
import os
import joblib
import pyshark
import numpy as np
import time
import csv

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
LIVE_CAPTURE    = True       # Set False to read from PCAP_FILE
PCAP_FILE       = os.path.expanduser('~/Desktop/sample.pcap')
INTERFACE       = 'en0'      # e.g., 'en0' or 'eth0'
PIPELINE_PATH   = os.path.expanduser('~/Desktop/rf_pipeline.pkl')
PREDICT_AFTER   = 5          # number of forward packets before predicting

# ─── LOAD MODEL ─────────────────────────────────────────────────────────────────
pipeline = joblib.load(PIPELINE_PATH)
print(f"✅ Loaded pipeline: {pipeline.named_steps}")

# ─── SETUP LOGGING ──────────────────────────────────────────────────────────────
# Raw packet log
raw_file = open(os.path.expanduser('~/Desktop/realtime_packets.csv'), 'w', newline='')
raw_writer = csv.writer(raw_file)
raw_writer.writerow([
    'timestamp','src_ip','src_port','dst_ip','dst_port',
    'protocol','length','hdr_ip_len','hdr_tcp_len','ack_flag','init_window'
])
# Feature dataset log
features_file = open(os.path.expanduser('~/Desktop/realtime_features.csv'), 'w', newline='')
feat_writer = csv.writer(features_file)
feature_list = [
    'Fwd Packet Length Max','Fwd Packet Length Min','Min Packet Length',
    'Max Packet Length','Average Packet Size','Fwd Packets/s',
    'Fwd Header Length','Fwd Header Length.1','min_seg_size_forward',
    'Total Length of Fwd Packets','Fwd Packet Length Std','Flow IAT Min',
    'Subflow Fwd Bytes','Destination Port','Protocol',
    'Packet Length Std','Flow Duration','Fwd IAT Total',
    'ACK Flag Count','Init_Win_bytes_forward','Flow IAT Mean',
    'Flow IAT Max','Fwd IAT Mean','Fwd IAT Max'
]
feat_writer.writerow(feature_list)

# ─── HELPERS ─────────────────────────────────────────────────────────────────────
def parse_ack_flag(pkt):
    raw = getattr(pkt.tcp, 'flags_ack', '0')
    return 1 if str(raw).lower() in ('true','1','yes') else 0

def new_flow(pkt):
    t0 = pkt.sniff_time.timestamp()
    return {
        'times_all':   [t0],
        'lengths_all': [float(pkt.length)],
        'fwd_times':   [t0],
        'fwd_lengths': [float(pkt.length)],
        'hdr_ip_fwd':  [float(pkt.ip.hdr_len)],
        'hdr_tcp_fwd': [float(pkt.tcp.hdr_len)],
        'init_window': float(pkt.tcp.window_size),
        'ack_flags':   [parse_ack_flag(pkt)],
        'dst_port':    int(pkt.tcp.dstport),
        'protocol':    int(pkt.ip.proto)
    }

# ─── CAPTURE SETUP ───────────────────────────────────────────────────────────────
cap = (pyshark.LiveCapture(interface=INTERFACE, bpf_filter='tcp')
       if LIVE_CAPTURE
       else pyshark.FileCapture(PCAP_FILE, keep_packets=False, bpf_filter='tcp'))
flows = {}
print("🕒 Starting capture...")

# ─── PACKET PROCESSING LOOP ─────────────────────────────────────────────────────
try:
    for pkt in cap.sniff_continuously():
        # Log raw packet data
        try:
            raw_writer.writerow([
                pkt.sniff_time, pkt.ip.src, pkt.tcp.srcport,
                pkt.ip.dst, pkt.tcp.dstport, pkt.ip.proto,
                pkt.length, pkt.ip.hdr_len, pkt.tcp.hdr_len,
                parse_ack_flag(pkt), pkt.tcp.window_size
            ])
        except Exception:
            pass

        # Flow key extraction
        try:
            key = (pkt.ip.src, pkt.tcp.srcport,
                   pkt.ip.dst, pkt.tcp.dstport,
                   pkt.ip.proto)
        except AttributeError:
            continue

        # initialize or update flow
        if key not in flows:
            flows[key] = new_flow(pkt)
            continue
        f = flows[key]
        ts = pkt.sniff_time.timestamp()
        length = float(pkt.length)
        f['times_all'].append(ts)
        f['lengths_all'].append(length)
        if pkt.ip.src == key[0] and pkt.ip.dst == key[2]:
            f['fwd_times'].append(ts)
            f['fwd_lengths'].append(length)
            f['hdr_ip_fwd'].append(float(pkt.ip.hdr_len))
            f['hdr_tcp_fwd'].append(float(pkt.tcp.hdr_len))
            f['ack_flags'].append(parse_ack_flag(pkt))

        # real-time prediction trigger
        if len(f['fwd_lengths']) == PREDICT_AFTER:
            all_len = np.array(f['lengths_all'])
            fwd_len = np.array(f['fwd_lengths'])
            all_times = np.array(f['times_all'])
            fwd_times = np.array(f['fwd_times'])
            flow_dur = all_times.max() - all_times.min()
            iat_all = np.diff(np.sort(all_times))
            iat_fwd = np.diff(np.sort(fwd_times))
            row = [
                fwd_len.max(), fwd_len.min(), all_len.min(), all_len.max(),
                all_len.mean(), len(fwd_len)/flow_dur if flow_dur > 0 else 0,
                np.mean(f['hdr_ip_fwd']), np.mean(f['hdr_tcp_fwd']),
                (fwd_len - np.array(f['hdr_tcp_fwd'])).min(), fwd_len.sum(),
                fwd_len.std(), iat_all.min() if iat_all.size>0 else 0,
                fwd_len.sum(), f['dst_port'], f['protocol'], all_len.std(),
                flow_dur, iat_fwd.sum() if iat_fwd.size>0 else 0,
                sum(f['ack_flags']), f['init_window'],
                iat_all.mean() if iat_all.size>0 else 0,
                iat_all.max() if iat_all.size>0 else 0,
                iat_fwd.mean() if iat_fwd.size>0 else 0,
                iat_fwd.max() if iat_fwd.size>0 else 0
            ]
            # Log features
            feat_writer.writerow(list(row))
            # Prediction
            pred = pipeline.predict(np.array(row).reshape(1, -1))[0]
            msg = f"Flow {key} → {'🚨 Attack!!' if pred == 1 else '✅ Normal'}"
            print(f"{pkt.sniff_time} | {msg}")
            if pred == 1:
                os.system(
                    f"terminal-notifier -title 'NIDS Alert' -message '{msg}' -sound default"
                )
            # Reset flow
            del flows[key]

except KeyboardInterrupt:
    print("\n🛑 Capture interrupted by user.")
finally:
    cap.close()
    raw_file.close()
    features_file.close()
    print("🛑 Capture ended.")
