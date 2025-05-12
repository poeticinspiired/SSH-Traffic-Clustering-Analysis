# 🧠 SSH Traffic Clustering Analysis

![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

This project processes network capture (PCAP/PCAPNG) files to analyze SSH traffic.
It extracts behavioral features and applies unsupervised learning (K-Means) to group SSH sessions based on traffic patterns.

---

## 🧰 Key Functionalities

- **🧬 Feature Extraction**: Packet size, inter-arrival time, source port, and protocol type.
- **🧠 Clustering**: K-Means algorithm groups similar SSH traffic behaviors.
- **📈 Optimization**: Elbow method & Silhouette score used to determine optimal clusters.
- **📊 Visualization**: Generates charts for cluster analysis and traffic patterns.
- **📂 Format Support**: Automatically handles both `.pcap` and `.pcapng` files using `tshark`.

---

## 📦 Prerequisites

Ensure the following are installed:

- **Python 3.6 or higher**
- Python packages:
  - `scapy`
  - `numpy`
  - `pandas`
  - `matplotlib`
  - `scikit-learn`
- **Wireshark with `tshark`** (for `.pcapng` file conversion)
  - [Install Wireshark](https://www.wireshark.org/download.html)
  - Add `tshark` to system PATH

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ssh-attack-clustering.git
cd ssh-attack-clustering
# SSH-Traffic-Clustering-Analysis
