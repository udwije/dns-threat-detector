"""
dns_threat_detector.py
DNS Threat Detection Terminal Prototype — CPU-Only
Project: Evaluation of Lexical ML Techniques for Passive DNS Threat Detection

Usage:
    python dns_threat_detector.py --init-config              # Generate default config.json
    python dns_threat_detector.py --sim                     # Simulation mode
    python dns_threat_detector.py --live                    # Live capture (requires Npcap/WinPcap)
    python dns_threat_detector.py --pcap yourfile.pcap     # PCAP replay mode
    python dns_threat_detector.py --domain google.com       # Single domain classification

Configuration:
    All paths, thresholds, and constants are read from config.json.
"""

import argparse
import csv
import json
import math
import os
import re
import time
import threading
import queue
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import tldextract

# =============================================================================
# DEFAULT CONFIGURATION
# =============================================================================

DEFAULT_CONFIG = {
    "paths": {
        "base_dir": ".",
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
        "trigram_unk_score": -10.0,
        "bigram_delim_start": "<",
        "bigram_delim_end": ">",
        "ngram_n": 2
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
    "pcap": {
        "delay_seconds": 0.08
    },
    "queue": {
        "maxsize": 500,
        "timeout_seconds": 60
    },
    "ui": {
        "domain_truncation_tui": 55,
        "domain_truncation_plain": 52
    }
}

CONFIG_PATH = Path("config.json")


def init_config():
    """Write default config.json if it doesn't exist."""
    if not CONFIG_PATH.exists():
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"Created default config: {CONFIG_PATH.resolve()}")
    else:
        print(f"Config already exists: {CONFIG_PATH.resolve()}")


def load_config():
    """Load config.json, falling back to defaults for missing keys."""
    if not CONFIG_PATH.exists():
        print("WARNING: config.json not found. Using defaults.")
        return DEFAULT_CONFIG
    with open(CONFIG_PATH, "r") as f:
        user_cfg = json.load(f)
    # Merge with defaults (shallow merge for top-level keys)
    cfg = dict(DEFAULT_CONFIG)
    for key, val in user_cfg.items():
        if key in cfg and isinstance(cfg[key], dict) and isinstance(val, dict):
            cfg[key].update(val)
        else:
            cfg[key] = val
    return cfg


# =============================================================================
# FEATURE NAMES (must match training notebook exactly — 21 features)
# =============================================================================

FEATURE_NAMES = [
    "shannon_entropy",
    "bigram_log_prob",
    "trigram_log_prob",
    "fqdn_len",
    "sld_len",
    "label_count",
    "longest_label",
    "avg_label_len",
    "digit_ratio",
    "vowel_ratio",
    "consonant_ratio",
    "is_common_tld",
    "max_label_entropy",
    "subdomain_char_len",
    "hex_ratio",
    "longest_consonant_run",
    "numeric_run_len",
    "label_length_variance",
    "label_entropy_mean",
    "label_entropy_variance",
    "ngram_diversity_index",
]


# =============================================================================
# ARTIFACT LOADING
# =============================================================================

def load_artifacts(cfg):
    """Load model, n-gram models, and scaler from configured paths."""
    base = Path(cfg["paths"]["base_dir"]).resolve()
    model_path = base / cfg["paths"]["model_file"]
    bigram_path = base / cfg["paths"]["bigram_model"]
    trigram_path = base / cfg["paths"]["trigram_model"]
    scaler_path = base / cfg["paths"]["scaler_file"]

    print("Loading model artifacts...")
    model = joblib.load(model_path)
    print(f"  model:         {model_path.name} OK")

    bigram_model = joblib.load(bigram_path)
    print(f"  bigram model:  {bigram_path.name} OK")

    trigram_model = joblib.load(trigram_path)
    print(f"  trigram model: {trigram_path.name} OK")

    scaler = joblib.load(scaler_path)
    print(f"  scaler:        {scaler_path.name} OK")

    return model, bigram_model, trigram_model, scaler


# =============================================================================
# FEATURE EXTRACTION (matches notebook exactly)
# =============================================================================

def _entropy(s):
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _bigram_log_prob(sld, model, cfg):
    """Log-probability under the benign bigram model (nested dict format)."""
    if not sld:
        return 0.0
    start = cfg["feature_engineering"]["bigram_delim_start"]
    end = cfg["feature_engineering"]["bigram_delim_end"]
    unk = cfg["feature_engineering"]["bigram_unk_score"]
    chars = [start] + list(sld.lower()) + [end]
    log_prob = 0.0
    for i in range(len(chars) - 1):
        p = model.get(chars[i], {}).get(chars[i + 1], 10 ** unk)
        log_prob += math.log(p)
    return log_prob / max(len(sld), 1)


def _trigram_log_prob(sld, model, cfg):
    """Log-probability under the benign trigram model (nested dict format)."""
    if not sld or len(sld) < 2:
        return 0.0
    start = cfg["feature_engineering"]["bigram_delim_start"]
    unk = cfg["feature_engineering"]["trigram_unk_score"]
    chars = [start, start] + list(sld.lower()) + [">"]
    log_prob = 0.0
    for i in range(len(chars) - 2):
        key = chars[i] + chars[i + 1]
        p = model.get(key, {}).get(chars[i + 2], 10 ** unk)
        log_prob += math.log(p)
    return log_prob / max(len(sld), 1)


def _label_length_variance(labels):
    if len(labels) < 2:
        return 0.0
    lengths = [len(l) for l in labels]
    mean = sum(lengths) / len(lengths)
    return sum((x - mean) ** 2 for x in lengths) / len(lengths)


def _label_entropy_mean(labels):
    if not labels:
        return 0.0
    return sum(_entropy(l) for l in labels) / len(labels)


def _label_entropy_variance(labels):
    if len(labels) < 2:
        return 0.0
    entropies = [_entropy(l) for l in labels]
    mean = sum(entropies) / len(entropies)
    return sum((e - mean) ** 2 for e in entropies) / len(entropies)


def _ngram_diversity_index(sld, n=2):
    if len(sld) < n:
        return 0.0
    ngrams = [sld[i:i + n] for i in range(len(sld) - n + 1)]
    return len(set(ngrams)) / len(ngrams)


def extract_raw_features(domain, bigram_model, trigram_model, cfg):
    """
    Extract all 21 lexical features from a domain string.
    Matches the notebook feature extraction exactly.
    """
    ext = tldextract.extract(domain)
    fqdn = domain.lower().strip().rstrip(".")
    labels = [l for l in fqdn.split(".") if l]

    # SLD extraction: use registered domain (tldextract.domain)
    # The notebook uses first-label for tunnel during training, but at
    # inference time we don't know the class, so we use the standard SLD.
    sld = ext.domain.lower() if ext.domain else ""

    tld = (ext.suffix or "").lower()
    common_tlds = set(cfg["feature_engineering"]["common_tlds"])
    hex_chars = set(cfg["feature_engineering"]["hex_chars"])
    vowels = set(cfg["feature_engineering"]["vowels"])
    consonants = set(cfg["feature_engineering"]["consonants"])

    denom = max(len(sld), 1)

    def ratio(charset):
        return sum(1 for c in sld if c in charset) / denom

    def longest_run(charset):
        pattern = "[" + re.escape("".join(sorted(charset))) + "]+"
        runs = re.findall(pattern, sld)
        return max((len(r) for r in runs), default=0)

    return {
        "shannon_entropy": _entropy(sld),
        "bigram_log_prob": _bigram_log_prob(sld, bigram_model, cfg),
        "trigram_log_prob": _trigram_log_prob(sld, trigram_model, cfg),
        "fqdn_len": len(fqdn),
        "sld_len": len(sld),
        "label_count": len(labels),
        "longest_label": max((len(l) for l in labels), default=0),
        "avg_label_len": sum(len(l) for l in labels) / max(len(labels), 1),
        "digit_ratio": ratio(set("0123456789")),
        "vowel_ratio": ratio(vowels),
        "consonant_ratio": ratio(consonants),
        "is_common_tld": int(tld.split(".")[-1] in common_tlds) if tld else 0,
        "max_label_entropy": max((_entropy(l) for l in labels), default=0.0),
        "subdomain_char_len": sum(len(l) for l in labels[:-2]) if len(labels) > 2 else 0,
        "hex_ratio": ratio(hex_chars),
        "longest_consonant_run": longest_run(consonants),
        "numeric_run_len": longest_run(set("0123456789")),
        "label_length_variance": _label_length_variance(labels),
        "label_entropy_mean": _label_entropy_mean(labels),
        "label_entropy_variance": _label_entropy_variance(labels),
        "ngram_diversity_index": _ngram_diversity_index(sld),
    }


# =============================================================================
# CLASSIFICATION
# =============================================================================

def classify_from_scaled(scaled_vector, model, cfg):
    """Classify from pre-scaled feature vector."""
    t0 = time.perf_counter()
    X = np.array(scaled_vector, dtype=float).reshape(1, -1)
    proba = model.predict_proba(X)[0]
    pred = int(np.argmax(proba))
    t1 = time.perf_counter()
    labels = cfg["classes"]["labels"]
    return pred, labels[str(pred)], round(float(proba[pred]) * 100, 2), (t1 - t0) * 1000


def classify_raw_domain(domain, model, bigram_model, trigram_model, scaler, cfg):
    """Extract features, scale, and classify a raw domain."""
    t0 = time.perf_counter()
    raw = extract_raw_features(domain, bigram_model, trigram_model, cfg)
    X_raw = np.array([raw[f] for f in FEATURE_NAMES], dtype=float)
    X_scaled = scaler.transform(X_raw.reshape(1, -1))[0]
    proba = model.predict_proba(X_scaled.reshape(1, -1))[0]
    pred = int(np.argmax(proba))
    t1 = time.perf_counter()
    labels = cfg["classes"]["labels"]
    return pred, labels[str(pred)], round(float(proba[pred]) * 100, 2), (t1 - t0) * 1000


# =============================================================================
# LOGGING
# =============================================================================

def init_log(log_path):
    """Initialize CSV log with headers."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", newline="") as f:
        csv.writer(f).writerow(
            ["timestamp", "domain", "class_int", "class_label", "confidence_pct", "latency_ms"]
        )


def log_result(log_path, domain, class_int, class_label, confidence, latency_ms):
    """Append a classification result to the log."""
    with open(log_path, "a", newline="") as f:
        csv.writer(f).writerow([
            datetime.now().isoformat(), domain,
            class_int, class_label,
            confidence, round(latency_ms, 4)
        ])


# =============================================================================
# DATA GENERATORS
# =============================================================================

def sim_generator(q, cfg):
    """Simulation mode: load pre-scaled test features."""
    base = Path(cfg["paths"]["base_dir"]).resolve()
    feat_path = base / cfg["paths"]["test_features_csv"]
    dom_path = base / cfg["paths"]["test_domains_csv"]

    print(f"Loading {feat_path.name} and {dom_path.name} ...")
    feat_df = pd.read_csv(feat_path)
    dom_df = pd.read_csv(dom_path, usecols=["domain", "class"])

    # Ensure alignment
    feat_df = feat_df.reset_index(drop=True)
    dom_df = dom_df.reset_index(drop=True)
    combined = pd.concat([dom_df[["domain", "class"]], feat_df[FEATURE_NAMES]], axis=1)

    n_per_class = cfg["simulation"]["samples_per_class"]
    rs = cfg["simulation"]["random_state"]
    sampled = (
        combined.groupby("class", group_keys=False)
        .apply(lambda x: x.sample(min(n_per_class, len(x)), random_state=rs))
        .sample(frac=1, random_state=rs)
        .reset_index(drop=True)
    )

    counts = sampled["class"].value_counts().sort_index()
    print(f"  {len(sampled)} samples: {counts.get(0, 0)} benign, {counts.get(1, 0)} DGA, {counts.get(2, 0)} tunnel. Starting...")

    delay = cfg["simulation"]["delay_seconds"]
    for _, row in sampled.iterrows():
        q.put((str(row["domain"]), row[FEATURE_NAMES].tolist(), "sim"))
        time.sleep(delay)
    q.put(None)


def live_generator(q, cfg):
    """Live capture mode using scapy."""
    try:
        from scapy.all import sniff, DNS, DNSQR
    except ImportError:
        print("ERROR: scapy not installed. Run: pip install scapy")
        q.put(None)
        return

    def handle(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
                if domain:
                    q.put((domain, None, "live"))
            except Exception:
                pass

    print("Live capture started on UDP port 53.")
    print("Browse the web or run ping to generate DNS traffic.")
    print("Press Ctrl+C to stop.\n")
    sniff(filter="udp port 53", prn=handle, store=False)


def pcap_generator(pcap_path, q, cfg):
    """PCAP replay mode."""
    try:
        from scapy.all import rdpcap, DNS, DNSQR
    except ImportError:
        print("ERROR: scapy not installed. Run: pip install scapy")
        q.put(None)
        return

    print(f"Replaying PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)
    count = 0
    delay = cfg["pcap"]["delay_seconds"]
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
                if domain:
                    q.put((domain, None, "pcap"))
                    count += 1
                    time.sleep(delay)
            except Exception:
                pass
    print(f"  Replayed {count} DNS queries.")
    q.put(None)


# =============================================================================
# UI / DISPLAY
# =============================================================================

def run_tui(q, model, bigram_model, trigram_model, scaler, cfg, mode="unknown"):
    """Run the Textual TUI if available, else fall back to plain terminal."""
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import Header, Footer, DataTable, Static
        from textual.reactive import reactive
        from textual import work
    except ImportError:
        print("Textual not installed. Run: pip install textual")
        run_plain(q, model, bigram_model, trigram_model, scaler, cfg, mode)
        return

    labels = cfg["classes"]["labels"]
    colors = cfg["classes"]["colors"]

    class StatsBar(Static):
        counts = reactive({labels["0"]: 0, labels["1"]: 0, labels["2"]: 0})
        total = reactive(0)
        avg_lat = reactive(0.0)
        mode = reactive("unknown")
        _lat_sum = 0.0

        def update_stats(self, label, latency_ms):
            c = dict(self.counts)
            c[label] = c.get(label, 0) + 1
            self.counts = c
            self.total = self.total + 1
            self._lat_sum += latency_ms
            self.avg_lat = self._lat_sum / self.total

        def render(self):
            c = self.counts
            mode_colors = {"sim": "blue", "live": "green", "pcap": "orange", "unknown": "gray"}
            mode_color = mode_colors.get(self.mode, "gray")
            return (
                f"[bold]Mode:[/bold] [{mode_color}]{self.mode.upper()}[/{mode_color}]  "
                f"[bold]Total:[/bold] {self.total}  "
                f"[green]Benign: {c.get(labels['0'], 0)}[/green]  "
                f"[red]DGA: {c.get(labels['1'], 0)}[/red]  "
                f"[yellow]Tunnel: {c.get(labels['2'], 0)}[/yellow]  "
                f"[cyan]Avg latency: {self.avg_lat:.3f} ms[/cyan]"
            )

    class DNSApp(App):
        CSS = """
        Screen { layout: vertical; }
        StatsBar {
            height: 3;
            border: solid $accent;
            padding: 0 2;
            content-align: center middle;
        }
        DataTable { height: 1fr; }
        """
        TITLE = "DNS Threat Detector"

        def __init__(self, q, model, bigram_model, trigram_model, scaler, cfg, log_path, mode="unknown"):
            super().__init__()
            self.q = q
            self.model = model
            self.bigram_model = bigram_model
            self.trigram_model = trigram_model
            self.scaler = scaler
            self.cfg = cfg
            self.log_path = log_path
            self.mode = mode

        def compose(self) -> ComposeResult:
            yield Header()
            yield StatsBar(id="stats")
            yield DataTable(id="table")
            yield Footer()

        def on_mount(self):
            self.query_one(DataTable).add_columns(
                "Domain", "Class", "Confidence", "Latency (ms)"
            )
            self.query_one("#stats", StatsBar).mode = self.mode
            self.process_queue()

        @work(thread=True)
        def process_queue(self):
            while True:
                try:
                    item = self.q.get(timeout=self.cfg["queue"]["timeout_seconds"])
                except Exception:
                    break
                if item is None:
                    break
                domain, features, mode = item
                if mode == "sim":
                    pred, label, conf, lat = classify_from_scaled(features, self.model, self.cfg)
                else:
                    pred, label, conf, lat = classify_raw_domain(
                        domain, self.model, self.bigram_model, self.trigram_model, self.scaler, self.cfg
                    )
                log_result(self.log_path, domain, pred, label, conf, lat)
                color = colors[str(pred)]
                trunc = self.cfg["ui"]["domain_truncation_tui"]
                short = domain[:trunc] + "..." if len(domain) > trunc else domain
                self.call_from_thread(self._add_row, short, label, conf, lat, color)
                self.call_from_thread(
                    self.query_one("#stats", StatsBar).update_stats, label, lat
                )

        def _add_row(self, domain, label, conf, lat, color):
            table = self.query_one(DataTable)
            table.add_row(
                domain,
                f"[{color}]{label}[/{color}]",
                f"{conf:.1f}%",
                f"{lat:.3f}",
            )
            table.scroll_end(animate=False)

    base = Path(cfg["paths"]["base_dir"]).resolve()
    results_dir = base / cfg["paths"]["results_dir"]
    log_path = results_dir / f"prototype_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    init_log(log_path)
    print(f"Results will be logged to: {log_path}\n")
    DNSApp(q, model, bigram_model, trigram_model, scaler, cfg, log_path, mode).run()


def run_plain(q, model, bigram_model, trigram_model, scaler, cfg, mode="unknown"):
    """Plain terminal output without TUI."""
    labels = cfg["classes"]["labels"]
    base = Path(cfg["paths"]["base_dir"]).resolve()
    results_dir = base / cfg["paths"]["results_dir"]
    log_path = results_dir / f"prototype_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    init_log(log_path)

    trunc = cfg["ui"]["domain_truncation_plain"]
    print("\n[MODE: " + mode.upper() + "]")
    print(f"{'Domain':<{trunc+3}} {'Class':<8} {'Conf':>7} {'Latency':>10}")
    print("-" * (trunc + 25))

    counts = Counter()
    lat_sum = 0.0
    total = 0

    while True:
        try:
            item = q.get(timeout=cfg["queue"]["timeout_seconds"])
        except Exception:
            break
        if item is None:
            break
        domain, features, mode = item
        if mode == "sim":
            pred, label, conf, lat = classify_from_scaled(features, model, cfg)
        else:
            pred, label, conf, lat = classify_raw_domain(
                domain, model, bigram_model, trigram_model, scaler, cfg
            )
        log_result(log_path, domain, pred, label, conf, lat)
        counts[label] += 1
        lat_sum += lat
        total += 1
        short = domain[:trunc] + "..." if len(domain) > trunc else domain
        print(f"{short:<{trunc+3}} {label:<8} {conf:>6.1f}% {lat:>8.3f}ms")

    print(f"\nDone. Total:{total}  Benign:{counts[labels['0']]}  "
          f"DGA:{counts[labels['1']]}  Tunnel:{counts[labels['2']]}")
    print(f"Log saved to {log_path}")


# =============================================================================
# SINGLE DOMAIN MODE
# =============================================================================

def classify_single(domain, model, bigram_model, trigram_model, scaler, cfg):
    """Classify a single domain and print detailed results."""
    pred, label, conf, lat = classify_raw_domain(
        domain, model, bigram_model, trigram_model, scaler, cfg
    )
    print(f"\nDomain:     {domain}")
    print(f"Prediction: {label} (class {pred})")
    print(f"Confidence: {conf}%")
    print(f"Latency:    {lat:.3f} ms")

    # Show per-class probabilities
    raw = extract_raw_features(domain, bigram_model, trigram_model, cfg)
    X_raw = np.array([raw[f] for f in FEATURE_NAMES], dtype=float)
    X_scaled = scaler.transform(X_raw.reshape(1, -1))
    proba = model.predict_proba(X_scaled)[0]
    labels = cfg["classes"]["labels"]
    print(f"\nPer-class probabilities:")
    for i in range(3):
        print(f"  {labels[str(i)]:8s}: {proba[i]*100:.2f}%")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="DNS Threat Detection Prototype (CPU-Only)")
    parser.add_argument("--init-config", action="store_true",
                        help="Generate default config.json and exit")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sim", action="store_true",
                       help="Simulation mode using pre-scaled test_features.csv")
    group.add_argument("--live", action="store_true",
                       help="Live DNS capture (requires Npcap/WinPcap)")
    group.add_argument("--pcap", metavar="FILE",
                       help="Replay DNS queries from a PCAP file")
    group.add_argument("--domain", metavar="DOMAIN",
                       help="Classify a single domain")
    args = parser.parse_args()

    if args.init_config:
        init_config()
        return

    cfg = load_config()
    model, bigram_model, trigram_model, scaler = load_artifacts(cfg)

    if args.domain:
        classify_single(args.domain, model, bigram_model, trigram_model, scaler, cfg)
        return

    q = queue.Queue(maxsize=cfg["queue"]["maxsize"])
    if args.sim:
        mode = "sim"
        t = threading.Thread(target=sim_generator, args=(q, cfg), daemon=True)
    elif args.live:
        mode = "live"
        t = threading.Thread(target=live_generator, args=(q, cfg), daemon=True)
    else:
        mode = "pcap"
        t = threading.Thread(target=pcap_generator, args=(args.pcap, q, cfg), daemon=True)
    t.start()
    run_tui(q, model, bigram_model, trigram_model, scaler, cfg, mode)


if __name__ == "__main__":
    main()
