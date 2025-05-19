# Network-Intrusion-Detection-System

# macOS DDoS Defender

An on-machine, ML-powered DDoS detection tool for macOS. Captures live TCP traffic, computes 24 flow-level features in real time, and classifies each flow with a Random Forest pipeline—all within ~200 ms. Issues native macOS notifications when a DDoS attack is detected.

---

## Features

- **Live packet capture** via PyShark / TShark  
- **Flow‐level feature extraction** (packet sizes, inter-arrival times, headers, flags, etc.)  
- **Real-time inference** with a scikit-learn `Pipeline` (MinMaxScaler + RandomForest)  
- **Native macOS alerts** (<200 ms latency)  
- **Modular design**: easily add new features, protocols, or auto-mitigation hooks  

---

## Prerequisites

1. **macOS 10.13+**  
2. **Homebrew**  
3. **Xcode Command Line Tools** (`xcode-select --install`)

---

## Installation

1. **Install Homebrew** (if you don’t have it):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

