# 🔒 DNS Threat Detector

> **Passive DNS Threat Detection via Lexical Machine Learning**

A CPU-only prototype for real-time classification of DNS queries into **Benign**, **DGA (Domain Generation Algorithm)**, and **DNS Tunneling** threats using 21 engineered lexical features and an XGBoost classifier.

---

## 📋 Overview

This project implements a production-ready DNS threat detection pipeline that operates entirely on **lexical domain features** — no deep packet inspection or external threat feeds required. It supports four operational modes:

| Mode | Description |
|------|-------------|
| 🎲 **Simulation** | Replay pre-scaled test features from CSV |
| 🌐 **Live Capture** | Real-time sniffing on UDP port 53 (via Scapy) |
| 📁 **PCAP Replay** | Batch analysis of captured `.pcap` files |
| 🎯 **Single Domain** | One-off classification of any domain string |

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  DNS Traffic    │────▶│ Feature Extractor │────▶│  XGBoost Model  │
│  (Live/PCAP/Sim)│     │ (21 lexical feats) │     │ (3-class classifier)
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                            │
                                                            ▼
                                                   ┌─────────────────┐
                                                   │  BENIGN / DGA   │
                                                   │   / TUNNEL      │
                                                   └─────────────────┘
```

### Feature Engineering (21 Features)

The model relies purely on **lexical/statistical features** extracted from domain strings:

| Category | Features |
|----------|----------|
| **Entropy** | Shannon entropy, max label entropy, label entropy mean/variance |
| **N-gram Models** | Bigram log-probability, trigram log-probability, n-gram diversity index |
| **Length** | FQDN length, SLD length, label count, longest label, avg label length, subdomain char length |
| **Character Composition** | Digit ratio, vowel ratio, consonant ratio, hex ratio, longest consonant run, numeric run length |
| **Structure** | Common TLD flag, label length variance |

> **N-gram models** are trained on benign domains to compute log-probabilities — DGA and tunnel domains score significantly lower.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Trained model artifacts (not included — train your own or request access)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dns-threat-detector.git
cd dns-threat-detector

# Install dependencies
pip install -r requirements.txt

# Optional: Install Scapy for live/PCAP modes
pip install scapy

# Optional: Install Textual for TUI dashboard
pip install textual
```

### Generate Default Config

```bash
python dns_threat_detector.py --init-config
```

This creates a `config.json` with default paths and thresholds. Customize as needed.

---

## 💻 Usage

### 1. Simulation Mode (Recommended for Testing)

Uses pre-scaled test features from `test_features.csv` — no feature extraction overhead.

```bash
python dns_threat_detector.py --sim
```

**Output:** Interactive TUI dashboard with real-time classification results.

### 2. Live Capture Mode

Sniffs DNS queries on UDP port 53 in real-time. Requires **Npcap** (Windows) or **libpcap** (Linux/macOS).

```bash
# Linux/macOS (sudo required for raw sockets)
sudo python dns_threat_detector.py --live

# Windows (run as Administrator)
python dns_threat_detector.py --live
```

### 3. PCAP Replay Mode

Analyze a previously captured `.pcap` file:

```bash
python dns_threat_detector.py --pcap capture.pcap
```

### 4. Single Domain Classification

Quick one-off prediction with per-class probability breakdown:

```bash
python dns_threat_detector.py --domain google.com
```

**Example Output:**
```
Domain:     google.com
Prediction: BENIGN (class 0)
Confidence: 99.2%
Latency:    0.847 ms

Per-class probabilities:
  BENIGN  : 99.23%
  DGA     :  0.45%
  TUNNEL  :  0.32%
```

---

## ⚙️ Configuration (`config.json`)

All paths, thresholds, and constants are externalized to `config.json`:

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

| Class | ID | Description | Typical Indicators |
|-------|-----|-------------|-------------------|
| **BENIGN** | 0 | Legitimate domains | High n-gram probability, balanced character distribution, common TLDs |
| **DGA** | 1 | Algorithmically generated domains | High entropy, low n-gram probability, random character patterns |
| **TUNNEL** | 2 | DNS tunneling (data exfiltration/C2) | Very long labels, high subdomain count, encoded data patterns |

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

## 🧪 Model Training (Separate Notebook)

The classifier is trained in a companion Jupyter notebook (not included in this repo) with the following pipeline:

1. **Data Collection** — Benign domains (Alexa/Tranco), DGA domains (OSINT feeds), DNS tunnel samples (iodine, dnscat2, etc.)
2. **Feature Extraction** — 21 lexical features per domain
3. **N-gram Modeling** — Character-level bigram/trigram models on benign corpus
4. **Scaling** — StandardScaler fit on training features
5. **Classification** — XGBoost with hyperparameter tuning (Optuna/grid search)
6. **Evaluation** — Accuracy, precision, recall, F1 per class + confusion matrix

> **Note:** Model artifacts (`*.pkl` files) are **not included** in this repository due to size. Train your own or contact the maintainers.

---

## 🖥️ UI Modes

### Rich TUI Dashboard (Textual)

When `textual` is installed, the app launches an interactive terminal UI:

- **Live data table** with color-coded threat classes
- **Real-time statistics bar** (counts per class + average latency)
- **Auto-scrolling** log view
- **Graceful fallback** to plain terminal if Textual is unavailable

### Plain Terminal Output

Minimal dependency mode — clean tabular output with CSV logging.

---

## 📝 Logging

All classifications are automatically logged to:

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

**Core:**
- `numpy`, `pandas` — Numerical computing
- `scikit-learn` — Scaling (StandardScaler)
- `xgboost` — Gradient boosted classifier
- `joblib` — Model serialization
- `tldextract` — Domain parsing

**Optional:**
- `scapy` — Live packet capture / PCAP reading
- `textual` — Rich terminal UI

---

## 🛡️ Limitations & Considerations

- **CPU-only** — Designed for edge deployment; no GPU required
- **Lexical-only** — Does not use DNS response data, TTL, or traffic volume (can be extended)
- **English-centric** — N-gram models trained on Latin-character domains
- **Label dependency** — Training data quality directly impacts detection accuracy
- **Not a replacement** for IDS/SIEM — Use as a complementary detection layer

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Benign domain corpus: [Tranco List](https://tranco-list.eu/)
- DGA research: [DGArchive](https://dgarchive.caad.fkie.fraunhofer.de/)
- DNS tunneling tools: iodine, dnscat2, dns2tcp (for synthetic tunnel data generation)

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional lexical features (homoglyph detection, punycode analysis)
- Multi-language n-gram support
- Integration with Zeek/Suricata
- Real-time dashboard (web-based)

---

> **Research Context:** This prototype was developed as part of an evaluation of lexical ML techniques for passive DNS threat detection. For academic use, please cite appropriately.
