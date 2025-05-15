import joblib
import pyshark
import numpy as np
import os

pipeline = joblib.load(os.path.expanduser('~/Desktop/rf_pipeline.pkl'))

def extract_features(pkt):

    length = float(pkt.length)
    is_tcp = 1.0 if pkt.highest_layer == 'TCP' else 0.0
    return [length, is_tcp]


cap = pyshark.FileCapture(
    os.path.expanduser('~/Desktop/sample.pcap'),
    keep_packets=False  # free memory as we go
)

for pkt in cap:
    try:
        feats = extract_features(pkt)
    except Exception:
        continue  # skip non-IP or malformed packets

    X = np.array(feats).reshape(1, -1)
    pred = pipeline.predict(X)[0]
    ts   = pkt.sniff_time

    if pred == 1:
        print(f"⚠️  [Attack] at {ts}  (layer={pkt.highest_layer})")
    else:
        print(f"✔️  [Normal] at {ts}")
