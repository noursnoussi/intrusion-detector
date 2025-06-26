import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib
import os

# Créer le dossier models/ s'il n'existe pas
os.makedirs("models", exist_ok=True)

# Charger les noms de colonnes
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent",
    "hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate", "target"
]


# Lire le fichier d'entraînement
df = pd.read_csv('data/KDDTrain+.txt', names=columns)

# Encoder les colonnes non numériques
for col in df.select_dtypes(include='object'):
    df[col] = LabelEncoder().fit_transform(df[col])

# Binariser la classe : normal = 0, attack = 1
# La classe "normal" a le label 11 après encodage (selon l'ordre dans KDDTrain+)
y = df['target']
y = y.apply(lambda x: 0 if x == 11 else 1)  # 0 = normal, 1 = attaque

X = df.drop(['target'], axis=1)

# Split en train/test pour évaluation
X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.3, random_state=42)

# Entraîner le modèle
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Évaluer
y_pred = model.predict(X_val)
print("📊 Rapport de classification :\n")
print(classification_report(y_val, y_pred, target_names=["Normal", "Attaque"]))

# Sauvegarder le modèle
joblib.dump(model, 'models/intrusion_model.pkl')
print("✅ Modèle sauvegardé dans models/intrusion_model.pkl")

