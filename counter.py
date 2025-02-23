# import re
# import os
# import time
# import joblib
# import numpy as np
# import pandas as pd
# from datetime import datetime
# from sklearn.feature_extraction.text import TfidfVectorizer
# from sklearn.ensemble import IsolationForest

# # Détection automatique du système pour définir le fichier de log
# if os.name == "nt":
#     LOG_FILE = "C:\\Users\\martin\\firewall.log"  # Windows
# else:
#     LOG_FILE = "/var/log/firewall.log"  # Linux/macOS

# DETECTION_LOG = "detection_log.log"
# MODEL_FILE = "sql_injection_model.pkl"
# DEBUG_MODE = True  # Active l'affichage des logs filtrés
# CSV_FILE = "datasqlfrKaggle/sqli.csv"  # Fichier du dataset d'injections SQL
# USE_CSV_DATASET = True  # Active l'entraînement avec des attaques SQL réelles

# # Détection d'injections SQL - Patterns communs améliorés
# SQL_PATTERNS = [
#     r"\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER)\b.*?(FROM|WHERE|VALUES|SET)",
#     r"(--|#|/\*|\*/|;|\bOR\b|\bAND\b).*?(\b1=1\b|\btrue\b|\bfalse\b)",
#     r"(\badmin\b|\broot\b|\bpassword\b|\buser\b).*?(=|'|\")"
# ]

# HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

# def load_logs():
#     """ Charge les logs depuis le fichier firewall."""
#     if not os.path.exists(LOG_FILE):
#         print(f"[WARNING] Log file {LOG_FILE} not found.")
#         return []

#     with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
#         logs = [line.strip() for line in file.readlines() if line.strip()]

#     return logs

# def load_csv_logs(csv_file):
#     """ Charge un dataset d'exemples d'injections SQL pour entraînement et test."""
#     if not os.path.exists(csv_file):
#         print(f"[ERROR] CSV file {csv_file} not found.")
#         return []

#     try:
#         df = pd.read_csv(csv_file, encoding="utf-16")
#     except UnicodeDecodeError:
#         print("[ERROR] Unicode decoding error while reading CSV. Trying with ISO-8859-1 encoding.")
#         df = pd.read_csv(csv_file, encoding="ISO-8859-1")

#     if "Sentence" not in df.columns:
#         print("[ERROR] Column 'Sentence' not found in CSV.")
#         return []

#     sql_queries = df["Sentence"].dropna().tolist()
#     print(f"[INFO] Loaded {len(sql_queries)} SQL injection examples.")
#     return sql_queries

# def extract_ip(line):
#     """ Extrait l'adresse IP (IPv4 ou IPv6) d'une ligne de log. """
#     ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b", line)
#     return ip_match.group() if ip_match else "Unknown"

# def detect_sql_injection(line):
#     """ Détecte les injections SQL avec des patterns connus. """
#     for pattern in SQL_PATTERNS:
#         if re.search(pattern, line, re.IGNORECASE):
#             return True
#     return False

# def load_model():
#     """ Charge le modèle de détection s'il existe, sinon l'entraîne. """
#     if os.path.exists(MODEL_FILE):
#         return joblib.load(MODEL_FILE)
#     logs = load_logs()
#     return train_model(logs)

# def test_sql_injection_detection():
#     """ Vérifie la précision du modèle sur des injections SQL connues."""
#     model, vectorizer = load_model()
#     if model is None or vectorizer is None:
#         print("[ERROR] Model loading failed. Skipping test.")
#         return

#     sql_queries = load_csv_logs(CSV_FILE)
#     if not sql_queries:
#         print("[INFO] No SQL injection samples found for testing.")
#         return

#     X_test = vectorizer.transform(sql_queries)
#     predictions = model.predict(X_test.toarray())

#     detected = sum(1 for p in predictions if p == -1)
#     print(f"[TEST RESULT] {detected}/{len(sql_queries)} SQL injection attempts detected.")

# def extract_features(logs):
#     """ Transforme les logs en vecteurs pour l'IA. """
#     if not logs:
#         return None, None
#     vectorizer = TfidfVectorizer()
#     return vectorizer.fit_transform(logs), vectorizer

# def analyze_logs():
#     """ Analyse les logs en temps réel et détecte les attaques SQL. """
#     model, vectorizer = load_model()
#     if model is None or vectorizer is None:
#         print("[ERROR] Model loading failed. Exiting analysis.")
#         return

#     logs = load_logs()
#     if not logs:
#         print("[INFO] No new logs to analyze.")
#         return

#     X_logs = vectorizer.transform(logs)
#     predictions = model.predict(X_logs.toarray())

#     with open(DETECTION_LOG, "a") as log_file:
#         for i, line in enumerate(logs):
#             ip = extract_ip(line)
#             if detect_sql_injection(line) or predictions[i] == -1:
#                 timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#                 log_entry = f"[{timestamp}] Suspicious SQL Injection Attempt Detected from {ip}: {line}\n"
#                 print(log_entry)
#                 log_file.write(log_entry)

# if __name__ == "__main__":
#     print("[INFO] Starting SQL Injection Detection...")
#     analyze_logs()
#     test_sql_injection_detection()

import re
import os
import time
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report

# Détection automatique du système pour définir le fichier de log
if os.name == "nt":
    LOG_FILE = "C:\\Users\\martin\\firewall.log"  # Windows
else:
    LOG_FILE = "/var/log/firewall.log"  # Linux/macOS

DETECTION_LOG = "detection_log.log"
MODEL_FILE = "sql_injection_model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"
DEBUG_MODE = True  # Active l'affichage des logs filtrés
CSV_FILE = "datasqlfrKaggle/sqli.csv"  # Fichier du dataset d'injections SQL
USE_CSV_DATASET = True  # Active l'entraînement avec des attaques SQL réelles

# Détection d'injections SQL - Patterns communs améliorés
SQL_PATTERNS = [
    r"\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER)\b.*?(FROM|WHERE|VALUES|SET)",
    r"(--|#|/\*|\*/|;|\bOR\b|\bAND\b).*?(\b1=1\b|\btrue\b|\bfalse\b)",
    r"(\badmin\b|\broot\b|\bpassword\b|\buser\b).*?(=|'|\")"
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

def load_logs():
    """ Charge les logs depuis le fichier firewall."""
    if not os.path.exists(LOG_FILE):
        print(f"[WARNING] Log file {LOG_FILE} not found.")
        return []

    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
        logs = [line.strip() for line in file.readlines() if line.strip()]

    return logs

def load_csv_logs(csv_file):
    """ Charge un dataset d'exemples d'injections SQL pour entraînement et test."""
    if not os.path.exists(csv_file):
        print(f"[ERROR] CSV file {csv_file} not found.")
        return []

    try:
        df = pd.read_csv(csv_file, encoding="utf-16")
    except UnicodeDecodeError:
        print("[ERROR] Unicode decoding error while reading CSV. Trying with ISO-8859-1 encoding.")
        df = pd.read_csv(csv_file, encoding="ISO-8859-1")

    if "Sentence" not in df.columns:
        print("[ERROR] Column 'Sentence' not found in CSV.")
        return []

    sql_queries = df["Sentence"].dropna().tolist()
    print(f"[INFO] Loaded {len(sql_queries)} SQL injection examples.")
    return sql_queries

def extract_ip(line):
    """ Extrait l'adresse IP (IPv4 ou IPv6) d'une ligne de log. """
    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b", line)
    return ip_match.group() if ip_match else "Unknown"

def detect_sql_injection(line):
    """ Détecte les injections SQL avec des patterns connus. """
    for pattern in SQL_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def load_model():
    """ Charge le modèle de détection s'il existe, sinon l'entraîne. """
    if os.path.exists(MODEL_FILE) and os.path.exists(VECTORIZER_FILE):
        model = joblib.load(MODEL_FILE)
        vectorizer = joblib.load(VECTORIZER_FILE)
        return model, vectorizer
    logs = load_logs()
    return train_model(logs)

def train_model(logs):
    """ Entraîne un nouveau modèle avec les logs fournis. """
    X, vectorizer = extract_features(logs)
    y = np.array([1 if detect_sql_injection(log) else 0 for log in logs])

    model = SGDClassifier(loss="hinge", max_iter=1000, tol=1e-3)
    model.fit(X, y)

    joblib.dump(model, MODEL_FILE)
    joblib.dump(vectorizer, VECTORIZER_FILE)

    return model, vectorizer

def test_sql_injection_detection():
    """ Vérifie la précision du modèle sur des injections SQL connues."""
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        print("[ERROR] Model loading failed. Skipping test.")
        return

    sql_queries = load_csv_logs(CSV_FILE)
    if not sql_queries:
        print("[INFO] No SQL injection samples found for testing.")
        return

    X_test = vectorizer.transform(sql_queries)
    predictions = model.predict(X_test)

    detected = sum(1 for p in predictions if p == 1)
    print(f"[TEST RESULT] {detected}/{len(sql_queries)} SQL injection attempts detected.")
    print(classification_report(np.ones(len(sql_queries)), predictions, target_names=["Non-SQLi", "SQLi"]))

def extract_features(logs):
    """ Transforme les logs en vecteurs pour l'IA. """
    if not logs:
        return None, None
    vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer="char")
    return vectorizer.fit_transform(logs), vectorizer

def analyze_logs():
    """ Analyse les logs en temps réel et détecte les attaques SQL. """
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        print("[ERROR] Model loading failed. Exiting analysis.")
        return

    logs = load_logs()
    if not logs:
        print("[INFO] No new logs to analyze.")
        return

    X_logs = vectorizer.transform(logs)
    predictions = model.predict(X_logs)

    with open(DETECTION_LOG, "a") as log_file:
        for i, line in enumerate(logs):
            ip = extract_ip(line)
            if detect_sql_injection(line) or predictions[i] == 1:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"[{timestamp}] Suspicious SQL Injection Attempt Detected from {ip}: {line}\n"
                print(log_entry)
                log_file.write(log_entry)

def incremental_training():
    """ Retrains the model incrementally with new data. """
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        print("[ERROR] Model loading failed. Exiting incremental training.")
        return

    new_logs = load_logs()
    if not new_logs:
        print("[INFO] No new logs for incremental training.")
        return

    X_new, _ = extract_features(new_logs)
    y_new = np.array([1 if detect_sql_injection(log) else 0 for log in new_logs])

    model.partial_fit(X_new, y_new)
    joblib.dump(model, MODEL_FILE)
    print("[INFO] Model incrementally trained with new data.")

if __name__ == "__main__":
    print("[INFO] Starting SQL Injection Detection...")
    analyze_logs()
    test_sql_injection_detection()
    incremental_training()