import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP

# Charger les paquets
packets = rdpcap("arp.pcapng")

# Colonnes attendues par le modèle
model_columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

extracted_data = []

for pkt in packets:
    row = {col: 0 for col in model_columns}  # Valeurs par défaut
    
    # Duration = on utilise 0 (ou on peut calculer le temps entre paquets)
    row["duration"] = 0
    
    # Type de protocole
    if ARP in pkt:
        row["protocol_type"] = "arp"
        row["service"] = "arp"
    elif TCP in pkt:
        row["protocol_type"] = "tcp"
        row["service"] = "http"  # par défaut
    elif UDP in pkt:
        row["protocol_type"] = "udp"
        row["service"] = "domain_u"
    elif ICMP in pkt:
        row["protocol_type"] = "icmp"
        row["service"] = "eco_i"
    else:
        row["protocol_type"] = "other"
        row["service"] = "other"

    row["flag"] = "SF"  # Par défaut

    # Données transférées (si IP)
    if IP in pkt:
        row["src_bytes"] = len(pkt[IP].payload)
        row["dst_bytes"] = len(pkt[IP])
    else:
        row["src_bytes"] = 0
        row["dst_bytes"] = 0

    # Exemple : land = 1 si IP source == IP dest
    if IP in pkt and pkt[IP].src == pkt[IP].dst:
        row["land"] = 1

    # Champs statistiques simulés
    row["count"] = 1
    row["srv_count"] = 1
    row["same_srv_rate"] = 1.0
    row["dst_host_count"] = 1
    row["dst_host_srv_count"] = 1
    row["dst_host_same_srv_rate"] = 1.0

    # Toutes les autres restent à 0

    extracted_data.append(row)

# Sauvegarder en CSV
df = pd.DataFrame(extracted_data)
df.to_csv("smart_arp_dataset.csv", index=False)
print("Dataset généré : smart_arp_dataset.csv")
