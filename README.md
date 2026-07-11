<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=2,6,12,18&height=200&section=header&text=DNS%20Threat%20Detector&fontSize=50&fontColor=ffffff&fontAlignY=40&desc=Real-time%20DNS%20Threat%20Classification&descAlignY=60&descSize=18&animation=fadeIn" alt="DNS Threat Detector Banner">

<br>

### 🔒 Passive DNS Threat Detection via Lexical Machine Learning

<br>

<img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/CPU%20Only-No%20GPU%20Required-00C853?style=for-the-badge">
<img src="https://img.shields.io/badge/XGBoost-Powered-EB5E28?style=for-the-badge">
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
<img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=for-the-badge">

<br>

<img src="https://img.shields.io/badge/Modes-Sim%20%7C%20Live%20%7C%20PCAP%20%7C%20Single-9146FF?style=flat-square">
<img src="https://img.shields.io/badge/Features-21%20Lexical-FF6B6B?style=flat-square">
<img src="https://img.shields.io/badge/Classes-Benign%20%7C%20DGA%20%7C%20Tunnel-4ECDC4?style=flat-square">

<br><br>

</div>

---

## 📋 Overview

This project runs a full DNS threat detection pipeline that works only on **lexical domain features**. It does not need deep packet inspection or outside threat feeds. It sorts DNS queries into three groups: **Benign**, **DGA (Domain Generation Algorithm)**, and **DNS Tunneling**. It uses 21 hand built lexical features and an XGBoost classifier.

<div align="center">

| Mode | Description |
|:---:|:---|
| 🎲 | **Simulation** — Replay pre-scaled test features from CSV |
| 🌐 | **Live Capture** — Real-time sniffing on UDP port 53 (via Scapy) |
| 📁 | **PCAP Replay** — Batch analysis of captured `.pcap` files |

</div>

---

## 🏗️ Architecture

```
┌─────────────────────┐
│      DNS Traffic    │
│  Live / PCAP / Sim  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Feature Extraction  │
│ 21 Lexical Features │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   XGBoost Model     │
│ 3-Class Classifier  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│     Prediction      │
│  BENIGN │ DGA │     │
│    DNS TUNNEL       │
└─────────────────────┘
```

### 🧬 Feature Engineering (21 Features)

The model only uses **lexical and statistical features** pulled from domain strings.

| Category | Features |
|:---|:---|
| 🔢 **Entropy** | Shannon entropy, max label entropy, label entropy mean and variance |
| 🔤 **N-gram Models** | Bigram log probability, trigram log probability, n-gram diversity index |
| 📏 **Length** | FQDN length, SLD length, label count, longest label, average label length, subdomain char length |
| 🧩 **Character Composition** | Digit ratio, vowel ratio, consonant ratio, hex ratio, longest consonant run, numeric run length |
| 🏗️ **Structure** | Common TLD flag, label length variance |

> 💡 **N-gram models** are trained on benign domains to score log probability. DGA and tunnel domains score much lower.

---

## 🚀 Quick Start

### ✅ Prerequisites

- Python 3.8+
- Trained model files (not included, train your own or ask for access)

### 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dns-threat-detector.git
cd dns-threat-detector

# Install dependencies
pip install -r requirements.txt

# Optional: install Scapy for live and PCAP modes
pip install scapy

# Optional: install Textual for the TUI dashboard
pip install textual
```

### ⚙️ Generate Default Config

```bash
python dns_threat_detector.py --init-config
```

This makes a `config.json` file with default paths and thresholds. Change it as you need.

---

## 💻 Usage

### 1️⃣ Simulation Mode (best for testing)

Uses pre-scaled test features from `test_features.csv`. No feature extraction cost.

```bash
python dns_threat_detector.py --sim
```

**Output:** An interactive TUI dashboard with live results.

### 2️⃣ Live Capture Mode

Watches DNS queries on UDP port 53 in real time. Needs **Npcap** on Windows or **libpcap** on Linux and macOS.

```bash
# Linux/macOS (sudo needed for raw sockets)
sudo python dns_threat_detector.py --live

# Windows (run as Administrator)
python dns_threat_detector.py --live
```

### 3️⃣ PCAP Replay Mode

Analyze a saved `.pcap` file:

```bash
python dns_threat_detector.py --pcap capture.pcap
```
---

## ⚙️ Configuration (`config.json`)

All paths, thresholds, and constants live in `config.json`.

```json
{
  "paths": {
    "model_file": "models/xgboost_tuned.pkl",
    "bigram_model": "DataSources/preprocessed/bigram_model.pkl",
    "trigram_model": "DataSources/preprocessed/trigram_model.pkl",
    "scaler_file": "DataSources/preprocessed/scaler.pkl",
    "test_features_csv": "DataSources/preprocessed/test_features.csv",
    "test_domains_csv": "DataSources/preprocessed/test_domains.csv",
    "results_dir": "results"
  },
  "feature_engineering": {
    "common_tlds": ["com", "net", "org", "io", "co", "uk", "de", "fr"],
    "hex_chars": "0123456789abcdef",
    "vowels": "aeiou",
    "consonants": "bcdfghjklmnpqrstvwxyz",
    "bigram_unk_score": -10.0,
    "trigram_unk_score": -10.0
  },
  "classes": {
    "labels": {"0": "BENIGN", "1": "DGA", "2": "TUNNEL"},
    "colors": {"0": "green", "1": "red", "2": "yellow"}
  },
  "simulation": {
    "samples_per_class": 30,
    "random_state": 42,
    "delay_seconds": 0.12
  },
  "queue": {
    "maxsize": 500,
    "timeout_seconds": 60
  }
}
```

---

## 📊 Threat Classes

<div align="center">

| Class | ID | Description | Typical Signs |
|:---:|:---:|:---|:---|
| 🟢 **BENIGN** | 0 | Real domains | High n-gram probability, balanced characters, common TLDs |
| 🔴 **DGA** | 1 | Auto-generated domains | High entropy, low n-gram probability, random characters |
| 🟡 **TUNNEL** | 2 | DNS tunneling (data theft/C2) | Very long labels, many subdomains, encoded data patterns |

</div>

---

## 📁 Project Structure

```
dns-threat-detector/
├── dns_threat_detector.py      # Main application (all modes)
├── config.json                 # Runtime configuration
├── requirements.txt            # Python dependencies
├── models/
│   └── xgboost_tuned.pkl       # Trained XGBoost classifier
├── DataSources/
│   └── preprocessed/
│       ├── bigram_model.pkl    # Benign bigram language model
│       ├── trigram_model.pkl   # Benign trigram language model
│       ├── scaler.pkl          # StandardScaler fitted on training data
│       ├── test_features.csv   # Pre-scaled test features (simulation mode)
│       └── test_domains.csv    # Domain labels for test set
└── results/
    └── prototype_log_*.csv     # Classification logs (auto-generated)
```

---

## 🧪 Model Training

The classifier is trained in a companion Jupyter notebook, not included in this repo. The steps are:

1. 📥 **Data Collection** — Benign domains (Alexa/Tranco), DGA domains (OSINT feeds), DNS tunnel samples (iodine)
2. 🧬 **Feature Extraction** — 21 lexical features per domain
3. 🔤 **N-gram Modeling** — Character-level bigram and trigram models on the benign set
4. 📐 **Scaling** — StandardScaler fit on the training features
5. 🌳 **Classification** — XGBoost with hyperparameter tuning (Optuna/grid search)
6. 📈 **Evaluation** — Accuracy, precision, recall, F1 per class, plus a confusion matrix


---

## 🖥️ UI Modes

### 🎨 Rich TUI Dashboard (Textual)

When `textual` is installed, the app opens an interactive terminal UI with:

- 📊 A live data table with color coded threat classes
- 📈 A real-time stats bar (counts per class plus average latency)
- 📜 Auto-scrolling log view
- 🔁 Graceful fallback to plain terminal if Textual is missing

### 🖨️ Plain Terminal Output

A minimal dependency mode with clean table output and CSV logging.

---

## 📝 Logging

All classifications are logged to:

```
results/prototype_log_YYYYMMDD_HHMMSS.csv
```

**Columns:**
- `timestamp` — ISO 8601 timestamp
- `domain` — Full domain string
- `class_int` — Numeric prediction (0/1/2)
- `class_label` — BENIGN/DGA/TUNNEL
- `confidence_pct` — Model confidence (0-100)
- `latency_ms` — Inference latency in milliseconds

---

## 🔧 Dependencies

<div align="center">

**Core**

<img src="https://img.shields.io/badge/numpy-013243?style=flat-square&logo=numpy&logoColor=white">
<img src="https://img.shields.io/badge/pandas-150458?style=flat-square&logo=pandas&logoColor=white">
<img src="https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikit-learn&logoColor=white">
<img src="https://img.shields.io/badge/XGBoost-EB5E28?style=flat-square">
<img src="https://img.shields.io/badge/joblib-gray?style=flat-square">
<img src="https://img.shields.io/badge/tldextract-blue?style=flat-square">

**Optional**

<img src="https://img.shields.io/badge/scapy-red?style=flat-square">
<img src="https://img.shields.io/badge/textual-purple?style=flat-square">

</div>

---

## 📄 License

MIT License, see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Benign domain corpus: [Tranco List](https://tranco-list.eu/)
- DGA research: [DGArchive](https://dgarchive.caad.fkie.fraunhofer.de/)
- DNS tunneling tools: iodine (used to make tunnel data)

---

## 🤝 Contributing

Contributions are welcome. Some areas of interest:
- 🔍 More lexical features (homoglyph detection, punycode analysis)
- 🌐 Multi-language n-gram support
- 🔗 Integration with Zeek/Suricata
- 📊 A real-time web-based dashboard

---

<div align="center">

> **Research Context:** This prototype was built as part of a study on lexical ML techniques for passive DNS threat detection. Please cite it if you use it for academic work.

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=2,6,12,18&height=100&section=footer" alt="footer">

</div>
