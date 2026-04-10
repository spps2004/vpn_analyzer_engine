# VPN Traffic Analyzer — AI/ML Engine

> High-performance, unsupervised AI/ML engine for proactive cyber attack detection in VPN traffic.
> Analyzes PCAP files and flow data to identify brute-force, C2 beaconing, exfiltration, lateral movement, tunneling abuse, and more — before damage occurs.

---

## Architecture Overview

```
PCAP File (.pcap/.pcapng)
        │
        ▼
┌─────────────────────┐
│   PCAP Parser       │  ← Scapy (primary) / PyShark (fallback)
│  (pcap_parser.py)   │    Extracts 5-tuple flows + packet stats
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Feature Engineer   │  ← 90+ security-focused features
│(feature_engineer.py)│    Flow / Behavioral / VPN-specific /
│                     │    Beaconing / Entropy / Rolling stats
└────────┬────────────┘
         │
    ┌────┴─────┐
    ▼          ▼
┌──────────┐ ┌──────────┐
│ ML Engine│ │Rule Engine│  ← 12 deterministic attack rules
│          │ │          │
│ • IF     │ └─────┬────┘
│ • AE(PT) │       │
│ • LOF    │       │
└────┬─────┘       │
     └──────┬──────┘
            ▼
   ┌─────────────────┐
   │ Ensemble Scorer │   IF(40%) + AE(40%) + LOF(20%) + Rules
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │Threat Classifier│   Maps scores → attack categories + explanations
   └────────┬────────┘
            ▼
     JSON Output (risk score, anomalies, chart data)
```

---

## Quick Start

### Installation

```bash
git clone <repo>
cd vpn_analyzer

pip install -r requirements.txt
# PyTorch (strongly recommended for Autoencoder):
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Optional: PyShark (requires tshark/Wireshark installed on system)
pip install pyshark
```

### Analyze a PCAP File

```python
from analyzer import VPNTrafficAnalyzer

analyzer = VPNTrafficAnalyzer(
    sensitivity=0.85,                      # 0.0–1.0: higher = more sensitive
    known_malicious_ips=["1.2.3.4"],       # optional threat intel list
    use_gpu=False,                          # set True for CUDA acceleration
)

results = analyzer.analyze_pcap("vpn_traffic.pcap")

print(f"Risk Score : {results['overall_risk_score']}/100  ({results['risk_level']})")
print(f"Anomalies  : {len(results['anomalies'])}")
for anomaly in results['anomalies']:
    print(f"  [{anomaly['severity']}] {anomaly['attack_type']} — {anomaly['confidence']:.0%}")
    print(f"  {anomaly['description']}")
```

### Analyze Pre-Parsed Flows

```python
import pandas as pd
from analyzer import VPNTrafficAnalyzer

# Minimum required columns:
flow_df = pd.DataFrame([{
    "src_ip": "10.0.1.1", "dst_ip": "1.2.3.4",
    "src_port": 54321, "dst_port": 443,
    "protocol": "TCP", "timestamp": 1700000000.0,
    "duration_sec": 30.0, "total_bytes": 512000,
    "total_packets": 400, "fwd_bytes": 480000, "bwd_bytes": 32000,
}])

analyzer = VPNTrafficAnalyzer()
results = analyzer.analyze_flows(flow_df)
```

### Run the Demo

```bash
cd vpn_analyzer
python demo.py
# → Runs 117 synthetic flows (100 normal + 17 attack)
# → Detects: 2× Data Exfiltration, 5× C2 Beaconing
# → Processing time: ~3–4 seconds
```

---

## Output Structure

```json
{
  "overall_risk_score": 85,
  "risk_level": "Critical",
  "summary": {
    "total_flows": 50000,
    "normal_flows": 49200,
    "anomalous_flows": 800,
    "anomaly_rate_pct": 1.6,
    "unique_src_ips": 142,
    "unique_dst_ips": 3847,
    "rule_hits": 12
  },
  "anomalies": [
    {
      "severity": "Critical",
      "confidence": 0.94,
      "attack_type": "C2 Beaconing / Covert Channel",
      "affected_ips": ["192.168.1.55", "203.0.113.99"],
      "description": "Flow 192.168.1.55 → 203.0.113.99:443 (TCP) exhibits periodic beacon behavior. Packets arrive every ~60.0s with low timing jitter (CV=0.02), average payload size 64 bytes. Classic C2 implant check-in pattern.",
      "evidence_features": {
        "avg_inter_arrival_sec": 60.0,
        "timing_jitter_cv": 0.02,
        "avg_packet_bytes": 64.0,
        "known_malicious_dst": true,
        "triggered_rules": ["C2_BEACON_DETECTION", "KNOWN_MALICIOUS_IP"]
      },
      "timestamp_range": {
        "start": "2023-11-14T10:00:00Z",
        "end": "2023-11-14T10:15:00Z"
      },
      "flow_details": { "src_ip": "...", "dst_port": 443, "total_bytes": 1920 }
    }
  ],
  "chart_data": {
    "timeseries_anomaly_scores": [
      { "timestamp": "2023-11-14T10:00:00", "avg_anomaly_score": 0.12, "flow_count": 523 }
    ],
    "top_suspicious_flows": [...],
    "score_distribution": { "0.0-0.2": 48200, "0.8-1.0": 312 },
    "attack_type_counts": { "C2 Beaconing / Covert Channel": 5, "Data Exfiltration": 2 }
  }
}
```

---

## Feature Engineering (90 Features)

| Category | Features |
|---|---|
| **Flow-level** | packet_rate, byte_rate, bytes_per_packet, fwd/bwd ratios, IAT stats (mean/std/cv/min/max), TCP flag ratios (SYN/ACK/RST/FIN/PSH/URG), log-scaled sizes, payload entropy |
| **Behavioral** | src/dst connection frequency, fan-out count, unique ports per dst, repeat exact connections, hour/day-of-week, off-hours flag, byte/packet z-scores |
| **VPN-specific** | exfil_ratio, exfil_flag, asymmetry_ratio, port_scan_score/flag, suspicious_port, dns_tunnel_flag, https_c2_flag, brute_force_score, lateral_movement_score, dst_diversity |
| **Beaconing** | iat_regularity, beacon_score, beacon_flag, slow_exfil_flag |
| **Entropy** | dst_ip_entropy, dst_port_entropy, src_port_entropy, dga_score |
| **Rolling (1m/5m/30m)** | bytes_mean, packets_mean, conn_count per window, roll_byte_zscore, roll_conn_zscore |
| **Threat Intel** | dst/src_is_known_malicious, dst/src_is_private, internal_to_internal |
| **Composite** | c2_composite_score, exfil_composite_score, scan_composite_score, bf_composite_score |

---

## Detection Rules (12 Rules)

| Rule | Attack Type | Confidence |
|---|---|---|
| BRUTE_FORCE_DETECTION | Brute-force / Credential Stuffing | 0.70–0.95 |
| C2_BEACON_DETECTION | C2 Beaconing / Covert Channel | 0.88 |
| PORT_SCAN_DETECTION | Port Scanning / Reconnaissance | 0.60–0.92 |
| DATA_EXFILTRATION | Data Exfiltration | 0.55–0.90 |
| DNS_TUNNELING | Tunneling Abuse / DNS Covert Channel | 0.85 |
| LATERAL_MOVEMENT | Lateral Movement inside VPN | 0.82 |
| DDOS_PREPARATION | DDoS Preparation / Amplification | 0.75 |
| HTTPS_COVERT_CHANNEL | C2 Beaconing / Covert Channel | 0.72 |
| SYN_FLOOD | DDoS Preparation / Amplification | 0.88 |
| KNOWN_MALICIOUS_IP | C2 Beaconing / Covert Channel | 0.97 |
| SLOW_EXFIL | Data Exfiltration | 0.78 |
| VPN_PROTOCOL_ANOMALY | Tunneling Abuse / Pivot | 0.65 |

---

## ML Models

### Isolation Forest (`sklearn.ensemble.IsolationForest`)
- **Purpose**: Identifies flows that are "isolated" from the majority (hard to average)
- **Strength**: Fast, scales well to high-dimensional data, no normality assumption
- **Parameters**: 200 estimators, auto max_samples, contamination=0.05
- **Weight in ensemble**: 40% (65% when PyTorch unavailable)

### Autoencoder (PyTorch)
- **Architecture**: `Input → 64 → 32 → 16 → 32 → 64 → Output` with ReLU + Dropout
- **Purpose**: Learns to reconstruct normal traffic; high reconstruction error = anomaly
- **Anomaly score**: Per-sample MSE normalized by 95th-percentile training error
- **Training**: 20–80 epochs (adaptive), Adam + ReduceLROnPlateau, weight decay
- **Weight in ensemble**: 40%

### Local Outlier Factor (`sklearn.neighbors.LocalOutlierFactor`)
- **Purpose**: Density-based detection — finds flows in sparse regions of feature space
- **Mode**: `novelty=True` for inference on new data
- **Neighbors**: adaptive `min(20, n/50)`
- **Weight in ensemble**: 20%

### Ensemble Formula
```
final_score = 0.65 × IF_score + 0.35 × LOF_score          # without PyTorch
final_score = 0.40 × IF_score + 0.40 × AE_score + 0.20 × LOF_score  # with PyTorch
ensemble    = 0.65 × ML_score + 0.35 × rule_score          # + rule overlay
```

---

## Training

### Train on Your Own Data

```bash
cd vpn_analyzer
python training/train.py --output-dir models/saved --epochs 80
```

This will:
1. Generate 10,000 normal + 3,000 attack synthetic flows
2. Train IF, Autoencoder (if PyTorch available), and LOF on **normal traffic only**
3. Validate detection rates on attack samples (prints classification report)
4. Save models to `models/saved/`

### Using Real Labeled Data

```python
from training.train import SyntheticVPNDataGenerator
from features.feature_engineer import FeatureEngineer
from models.ml_engine import MLEngine
import pandas as pd

# Load your labeled PCAP-derived flows
normal_df = pd.read_csv("your_normal_flows.csv")

fe = FeatureEngineer()
normal_features = fe.extract_all_features(normal_df)

engine = MLEngine(model_dir="models/saved")
engine.fit_and_save(normal_features)  # train ONLY on normal data
```

### Improving Detection

**More training data**: Run on a week of baseline VPN traffic before deployment.

**Tune contamination**: Lower `contamination` in `MLEngine` (e.g., 0.01) for low false-positive environments.

**Tune sensitivity**: `VPNTrafficAnalyzer(sensitivity=0.7)` — lower = more alerts.

**Add threat intel**: Pass `known_malicious_ips=["ip1", "ip2"]` or load from a blocklist file.

**Add new rules**: Subclass `RuleEngine` and add rule methods following the `_rule_*` pattern.

**Improve Autoencoder**: Increase `epochs`, add batch normalization, tune `bottleneck_dim`.

---

## Performance

| File Size | Flows | Processing Time (no GPU) |
|---|---|---|
| 10 MB | ~5,000 | ~3s |
| 50 MB | ~25,000 | ~15s |
| 200 MB | ~100,000 | ~60–90s |
| 500 MB | ~250,000 | ~3–4 min |

*Rolling-window features are O(n²) per source IP bucket — the main bottleneck for large files.*
*For production use, consider disabling 30-minute windows (`time_windows=[60, 300]`).*

---

## VPN Protocol Support

| Protocol | Detection | Notes |
|---|---|---|
| WireGuard | ✅ UDP/51820 | Detected from port |
| OpenVPN UDP | ✅ UDP/1194 | Detected from port |
| OpenVPN TCP | ✅ TCP/1194, TCP/443 | Including TCP 443 overlap |
| IPsec/IKE | ✅ UDP/500, UDP/4500 | IKE negotiation traffic |
| L2TP | ✅ UDP/1701 | Often with IPsec |
| PPTP | ✅ TCP/1723 | Legacy support |
| GRE | ✅ Protocol 47 | Identified by IP proto |
| ESP/AH | ✅ Protocol 50/51 | IPsec encryption layer |

---

## File Structure

```
vpn_analyzer/
├── analyzer.py                  # VPNTrafficAnalyzer (main entry point)
├── demo.py                      # Quick-start demo script
├── requirements.txt
├── features/
│   ├── pcap_parser.py           # Scapy/PyShark PCAP → flow DataFrame
│   └── feature_engineer.py      # 90+ feature extraction
├── models/
│   ├── ml_engine.py             # IF + Autoencoder + LOF ensemble
│   └── saved/                   # Trained model artifacts (.joblib, .pt)
├── detection/
│   ├── rule_engine.py           # 12 deterministic attack rules
│   └── threat_classifier.py    # Score → attack type + explanation
└── training/
    └── train.py                 # Synthetic data + training pipeline
```

---

## Adding Custom Rules

```python
from detection.rule_engine import RuleEngine, RuleHit

class MyRuleEngine(RuleEngine):
    def __init__(self):
        super().__init__()
        self._rules.append(self._rule_custom_vpn_abuse)

    def _rule_custom_vpn_abuse(self, df):
        mask = (df.get("dst_port", 0) == 4444) & (df.get("total_bytes", 0) > 10000)
        indices = df.index[mask].tolist()
        if not indices:
            return None
        return RuleHit(
            rule_name="CUSTOM_C2_PORT",
            attack_type="C2 Beaconing / Covert Channel",
            confidence=0.90,
            severity="High",
            flow_indices=indices,
            description="Traffic to known C2 port 4444 with large payload.",
            evidence={"flagged_flows": len(indices)},
        )
```

---

## License

MIT — see `LICENSE` for details.
