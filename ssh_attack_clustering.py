import os
import subprocess
from scapy.all import rdpcap, TCP
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Convert .pcapng to .pcap using tshark
def convert_pcapng_to_pcap(pcapng_file):
    pcap_file = pcapng_file.replace('.pcapng', '.converted.pcap')
    try:
        subprocess.run(['tshark', '-F', 'pcap', '-r', pcapng_file, '-w', pcap_file], check=True)
        print(f"[+] Converted {pcapng_file} to {pcap_file}")
        return pcap_file
    except FileNotFoundError:
        print("[!] tshark not found. Please install Wireshark and ensure tshark is in your PATH.")
        return None
    except subprocess.CalledProcessError:
        print(f"[!] Failed to convert {pcapng_file}")
        return None

# Find all .pcap and .pcapng files
def find_all_pcap_files():
    files = []
    for file in os.listdir('.'):
        if file.endswith('.pcap') and not file.endswith('.converted.pcap'):
            files.append(file)
        elif file.endswith('.pcapng'):
            converted = convert_pcapng_to_pcap(file)
            if converted:
                files.append(converted)
    return files

# Extract SSH packets and features
def extract_features(pcap_file):
    print(f"[+] Processing {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error reading {pcap_file}: {e}")
        return None

    features = []
    timestamps = []

    for pkt in packets:
        if TCP in pkt and pkt[TCP].dport == 22:
            size = len(pkt)
            time = pkt.time
            src_port = pkt[TCP].sport
            proto = 6  # TCP is 6 in IP protocol numbers
            features.append((size, time, src_port, proto))
            timestamps.append(time)

    if not features:
        print(f"[!] No SSH packets found in {pcap_file}")
        return None

    df = pd.DataFrame(features, columns=["size", "time", "src_port", "proto"])
    df["inter_arrival"] = df["time"].diff().fillna(0)
    return df.drop("time", axis=1)

# Determine optimal cluster count using elbow and silhouette
def determine_optimal_k(X):
    distortions = []
    silhouettes = []
    K = range(2, 7)

    for k in K:
        kmeans = KMeans(n_clusters=k, random_state=42).fit(X)
        distortions.append(kmeans.inertia_)
        silhouettes.append(silhouette_score(X, kmeans.labels_))

    plt.figure(figsize=(12, 5))

    plt.subplot(1, 2, 1)
    plt.plot(K, distortions, 'bo-')
    plt.xlabel("Number of Clusters")
    plt.ylabel("Inertia")
    plt.title("Elbow Method")

    plt.subplot(1, 2, 2)
    plt.plot(K, silhouettes, 'go-')
    plt.xlabel("Number of Clusters")
    plt.ylabel("Silhouette Score")
    plt.title("Silhouette Score")

    plt.tight_layout()
    plt.savefig("clustering_analysis.png")
    plt.close()

    best_k = K[np.argmax(silhouettes)]
    print(f"[+] Optimal cluster count: {best_k}")
    return best_k

# Perform clustering and save plots
def cluster_and_visualize(df, k):
    X = df[["size", "inter_arrival", "src_port", "proto"]]
    kmeans = KMeans(n_clusters=k, random_state=42).fit(X)
    df["cluster"] = kmeans.labels_

    plt.figure(figsize=(8, 6))
    for label in df["cluster"].unique():
        cluster_data = df[df["cluster"] == label]
        plt.scatter(cluster_data["size"], cluster_data["inter_arrival"], label=f"Cluster {label}")
    plt.xlabel("Packet Size")
    plt.ylabel("Inter-arrival Time")
    plt.title("Cluster Visualization")
    plt.legend()
    plt.savefig("cluster_visualization.png")
    plt.close()

    return df

# Summary statistics
def print_summary(df):
    print("\n📊 Cluster Summary:")
    for cluster_id, group in df.groupby("cluster"):
        print(f"\nCluster {cluster_id}:")
        print(f"  Size: {len(group)}")
        print(f"  Avg Packet Size: {group['size'].mean():.2f}")
        print(f"  Avg Inter-arrival Time: {group['inter_arrival'].mean():.4f}")
        print(f"  Most Common Source Port: {group['src_port'].mode().iloc[0]}")

# Main pipeline
if __name__ == "__main__":
    pcap_files = find_all_pcap_files()
    if not pcap_files:
        print("[!] No PCAP files found.")
        exit(1)

    for pcap_file in pcap_files:
        df = extract_features(pcap_file)
        if df is None or df.empty:
            continue
        optimal_k = determine_optimal_k(df[["size", "inter_arrival", "src_port", "proto"]])
        df_clustered = cluster_and_visualize(df, optimal_k)
        print_summary(df_clustered)
