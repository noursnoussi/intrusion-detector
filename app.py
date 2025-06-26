import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

st.set_page_config(page_title="Détection d'intrusion réseau", layout="wide")
st.title("Détection d'Intrusion Réseau par Intelligence Artificielle")

model = joblib.load('models/intrusion_model.pkl')

st.markdown("""
Ce système utilise un modèle de **machine learning** entraîné sur le dataset NSL-KDD pour détecter automatiquement les connexions réseau anormales.
""")

uploaded_file = st.file_uploader("Importer un fichier réseau au format `.csv`", type=["csv"])

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)
        st.success("Fichier chargé avec succès !")
        st.write("Aperçu des données importées :", df.head())
        for col in df.select_dtypes(include='object'):
            df[col] = LabelEncoder().fit_transform(df[col])
        predictions = model.predict(df)
        df['prediction'] = predictions
        df['prediction'] = df['prediction'].map({0: 'Normal', 1: 'Attaque'})
        st.subheader("Résultats de la détection")
        st.write(df['prediction'].value_counts())

        st.subheader("Détails des connexions détectées")
        st.dataframe(df)

    except Exception as e:
        st.error(f"Erreur lors du traitement du fichier : {e}")
else:
    st.info("Veuillez importer un fichier CSV pour commencer l'analyse.")

