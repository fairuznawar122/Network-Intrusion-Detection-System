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

1. **Install Homebrew** (if you don’t have it):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
## Dependencies

### System (Homebrew)

| Package            | Purpose                                 |
|--------------------|-----------------------------------------|
| `wireshark`        | Provides **TShark** for live packet capture |
| `python`           | Installs the latest Python 3 runtime    |
| `terminal-notifier`| Displays native macOS banner alerts     |

> **Permission step**  
> Add your user to the `_access_bpf` group so TShark can read network interfaces:  
> ```bash
> sudo dseditgroup -o edit -a $(whoami) -t user _access_bpf
> ```

---

### Python (inside your virtual environment)

| Package         | Tested Version | Role                                |
|-----------------|---------------|-------------------------------------|
| `pyshark`       | ≥ 0.6         | Live/offline packet parsing         |
| `scikit-learn`  | ≥ 1.3         | `Pipeline`, `RandomForest`, scaler  |
| `numpy`         | ≥ 1.23        | Numeric feature calculations        |
| `joblib`        | ≥ 1.3         | Model serialization                 |
| `pandas` *(opt)*| ≥ 2.0         | DataFrame wrappers (optional)       |
| `matplotlib` *(opt)* | ≥ 3.7   | Plotting / visualization (optional) |

Install Python deps after activating your venv:

```bash
pip install pyshark scikit-learn numpy joblib
# optional extras
pip install pandas matplotlib

