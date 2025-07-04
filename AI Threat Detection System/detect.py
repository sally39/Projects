import numpy as np
import pandas as pd  # 📌 Added to handle feature names correctly
import joblib
from scapy.all import sniff, IP, TCP, UDP  # Import necessary Scapy modules

# Load the trained model
model = joblib.load("threat_detector.pkl")  # Ensure this file is in the same directory as detect.py

# Feature names (Must match the model's features exactly)
feature_names = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload",
    "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "is_sm_ips_ports",

    # One-hot encoded protocol fields
    "proto_3pc", "proto_a/n", "proto_aes-sp3-d", "proto_any", "proto_argus", "proto_aris",
    "proto_arp", "proto_ax.25", "proto_bbn-rcc", "proto_bna", "proto_br-sat-mon", "proto_cbt",
    "proto_cftp", "proto_chaos", "proto_compaq-peer", "proto_cphb", "proto_cpnx", "proto_crtp",
    "proto_crudp", "proto_dcn", "proto_ddp", "proto_ddx", "proto_dgp", "proto_egp", "proto_eigrp",
    "proto_emcon", "proto_encap", "proto_etherip", "proto_fc", "proto_fire", "proto_ggp",
    "proto_gmtp", "proto_gre", "proto_hmp", "proto_i-nlsp", "proto_iatp", "proto_ib", "proto_idpr",
    "proto_idpr-cmtp", "proto_idrp", "proto_ifmp", "proto_igmp", "proto_igp", "proto_il",
    "proto_ip", "proto_ipcomp", "proto_ipcv", "proto_ipip", "proto_iplt", "proto_ipnip",
    "proto_ippc", "proto_ipv6", "proto_ipv6-frag", "proto_ipv6-no", "proto_ipv6-opts",
    "proto_ipv6-route", "proto_ipx-n-ip", "proto_irtp", "proto_isis", "proto_iso-ip",
    "proto_iso-tp4", "proto_kryptolan", "proto_l2tp", "proto_larp", "proto_leaf-1", "proto_leaf-2",
    "proto_merit-inp", "proto_mfe-nsp", "proto_mhrp", "proto_micp", "proto_mobile", "proto_mtp",
    "proto_mux", "proto_narp", "proto_netblt", "proto_nsfnet-igp", "proto_nvp", "proto_ospf",
    "proto_pgm", "proto_pim", "proto_pipe", "proto_pnni", "proto_pri-enc", "proto_prm",
    "proto_ptp", "proto_pup", "proto_pvp", "proto_qnx", "proto_rdp", "proto_rsvp", "proto_rvd",
    "proto_sat-expak", "proto_sat-mon", "proto_sccopmce", "proto_scps", "proto_sctp",
    "proto_sdrp", "proto_secure-vmtp", "proto_sep", "proto_skip", "proto_sm", "proto_smp",
    "proto_snp", "proto_sprite-rpc", "proto_sps", "proto_srp", "proto_st2", "proto_stp",
    "proto_sun-nd", "proto_swipe", "proto_tcf", "proto_tcp", "proto_tlsp", "proto_tp++",
    "proto_trunk-1", "proto_trunk-2", "proto_ttp", "proto_udp", "proto_unas", "proto_uti",
    "proto_vines", "proto_visa", "proto_vmtp", "proto_vrrp", "proto_wb-expak", "proto_wb-mon",
    "proto_wsn", "proto_xnet", "proto_xns-idp", "proto_xtp", "proto_zero",

    # One-hot encoded service fields
    "service_-", "service_dhcp", "service_dns", "service_ftp", "service_ftp-data",
    "service_http", "service_irc", "service_pop3", "service_radius", "service_smtp",
    "service_snmp", "service_ssh", "service_ssl",

    # One-hot encoded state fields
    "state_ACC", "state_CLO", "state_CON", "state_FIN", "state_INT", "state_REQ", "state_RST",

    # One-hot encoded attack categories
    "attack_cat_Analysis", "attack_cat_Backdoor", "attack_cat_DoS", "attack_cat_Exploits",
    "attack_cat_Fuzzers", "attack_cat_Generic", "attack_cat_Normal", "attack_cat_Reconnaissance",
    "attack_cat_Shellcode", "attack_cat_Worms"
]

# Function to extract packet features
def extract_features(pkt):
    """Extracts network features from a live packet and ensures 192 features for ML."""
    if not pkt.haslayer(IP):
        print("❌ Skipping Non-IP Packet")
        return None  # Ignore non-IP packets

    try:
        # Initialize all features to zero
        features = {col: 0 for col in feature_names}

        # Extract numerical features
        features["dur"] = 0.001  # Placeholder (replace with real duration)
        features["spkts"] = 1
        features["sbytes"] = len(pkt)

        # One-hot encode protocol fields
        protocol_name = f"proto_{pkt.proto}" if hasattr(pkt, 'proto') else "proto_other"
        if protocol_name in features:
            features[protocol_name] = 1

        # One-hot encode service fields (unknown service default to 'service_other')
        detected_service = "service_other"
        if detected_service in features:
            features[detected_service] = 1

        # One-hot encode state fields
        state = "state_CON" if pkt.haslayer(TCP) else "state_INT"
        if state in features:
            features[state] = 1

        # One-hot encode attack categories (assume normal)
        features["attack_cat_Normal"] = 1  # Assume normal traffic

        # Ensure extracted features match training dataset order
        feature_values = np.array([features[col] for col in feature_names], dtype=float)

        # Debugging Output
        print(f"✅ Extracted {len(feature_values)} features: {feature_values[:5]}...")  # Print first 5

        return feature_values.reshape(1, -1)

    except Exception as e:
        print(f"❌ Feature Extraction Error: {e}")
        return None

# Detect threats from live packets
def detect_threat(pkt):
    """Checks a packet for threats using the trained model."""
    features = extract_features(pkt)
    if features is None:
        return  # Skip non-IP packets

    # Convert extracted features to DataFrame to match model's expected format
    features_df = pd.DataFrame(features, columns=feature_names)  # 🚀 FIXED!

    prediction = model.predict(features_df)  # ✅ Now it uses the correct feature names!

    print(f"🔎 Prediction: {prediction}")  # Debugging output

    if prediction[0] == 1:
        print(f"[⚠️ ALERT] Suspicious Packet Detected: {pkt.summary()}")

# Start network monitoring
print("🔍 Monitoring network traffic for threats... Press Ctrl+C to stop.")
sniff(prn=detect_threat, filter="ip", store=0)


from scapy.all import IP, TCP, send

# Define destination IP (you can change this to your test machine or localhost for safety)
destination_ip = "127.0.0.1"  # Use localhost for safe testing

# Craft a suspicious-looking TCP SYN packet
packet = IP(dst=destination_ip)/TCP(dport=80, flags="S")

# Send the packet
send(packet, verbose=0)

# Feedback to confirm the packet was sent
print(f"[INFO] Simulated suspicious TCP SYN packet sent to {destination_ip}:80")