# ML-powered DDoS detection tool for macOS


An on-machine, ML-powered DDoS detection tool for macOS. Captures live TCP traffic, computes 24 flow-level features in real time, and classifies each flow with a Random Forest pipeline—all within ~200 ms. Issue native macOS notifications when a DDoS attack is detected.


## Features

- **Live packet capture** via PyShark / TShark  
- **Flow‐level feature extraction** (packet sizes, inter-arrival times, headers, flags, etc.)  
- **Real-time inference** with a scikit-learn `Pipeline` (MinMaxScaler + RandomForest)  
- **Native macOS alerts** (<200 ms latency)  
- **Modular design**: easily add new features, protocols, or auto-mitigation hooks  


## Prerequisites

1. **macOS 10.13+**  
2. **Homebrew**  
3. **Xcode Command Line Tools** (`xcode-select --install`)

---

## Installation
1. Install Homebrew (if you don’t have it):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"


2. Install the following Dependencies 

| Package             | Purpose                                     |
|---------------------|---------------------------------------------|
| `wireshark`         | Provides **TShark** for live packet capture |
| `python`            | Installs the latest Python 3 runtime        |
| `terminal-notifier` | Displays native macOS banner alerts         |

> **Permission step**  
> Add your user to the `_access_bpf` group so TShark can read network interfaces:  
> ```bash
> sudo dseditgroup -o edit -a $(whoami) -t user _access_bpf
> ```
> Log out / log back in (or reboot) for the change to take effect.

3. Create & activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate   # prompt now shows (venv)
```


4. Install Python packages (inside your virtual environment)

| Package               | Tested Version | Role                               |
|-----------------------|---------------|-------------------------------------|
| `pyshark`             | ≥ 0.6         | Live/offline packet parsing         |
| `scikit-learn`        | ≥ 1.3         | `Pipeline`, `RandomForest`, scaler  |
| `numpy`               | ≥ 1.23        | Numeric feature calculations        |
| `joblib`              | ≥ 1.3         | Model serialization                 |
| `pandas` *(opt)*      | ≥ 2.0         | DataFrame wrappers (optional)       |
| `matplotlib` *(opt)*  | ≥ 3.7   | Plotting / visualization (optional)       |

Install Python deps after activating your venv:

```bash
pip install pyshark scikit-learn numpy joblib
# optional extras
pip install pandas matplotlib
```
---
5. Download `detect_flows.py` and `rf_pipeline.pkl`

6. Place `rf_pipeline.pkl` on your Desktop, or edit PIPELINE_PATH in `detect_flows.py` to point to the location of the `rf_pipeline.pkl` file on your device.

7. Run the following commands on your terminal for Live capture.
   ```bash
   source ~/nid_env/bin/activate # To activate the virtual environment
   sudo python3 detect_flows.py 
   # Make sure to update the location of the file
   # Example - sudo python3 /Users/fairuznawar/Desktop/detect_flows.py
   ```
   ---
   For Offline replay (PCAP)
   ```bash
   # edit detect_flows.py → LIVE_CAPTURE = False, PCAP_FILE = '/path/to/file.pcap'
   python detect_flows.py
   ```

---
## Demo 

The Attacks can also be verified with the captures from WireShark.

 
![Screenshot 2025-05-15 at 7 18 41 PM](https://github.com/user-attachments/assets/032ccd82-d6d1-4a35-bf4f-334e5f572fba)


https://github.com/user-attachments/assets/b8ea8b20-dd60-4043-a5c8-4aa922e4d1c0




---
### Additional Resources
The details of the implementation and study can be found in the report. <br>
Project Report  - https://shorturl.at/PvttS <br>
CIC-DDoS2019    - https://www.unb.ca/cic/datasets/ddos-2019.html
