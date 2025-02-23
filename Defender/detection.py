import os
import re
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier

# Define common SQL injection patterns
SQL_PATTERNS = [
    r"\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER)\b.*?(FROM|WHERE|VALUES|SET)",
    r"(--|#|/\*|\*/|;|\bOR\b|\bAND\b).*?(\b1=1\b|\btrue\b|\bfalse\b)",
    r"(\badmin\b|\broot\b|\bpassword\b|\buser\b).*?(=|'|\")"
]

class Defender:
    def __init__(self, model_file='sql_injection_model.pkl', vectorizer_file='vectorizer.pkl', log_file="/var/log/firewall.log"):
        self.model_file = model_file
        self.vectorizer_file = vectorizer_file
        self.log_file = log_file
        self.model = None
        self.vectorizer = None
        self.load_or_train_model()
    
    def load_logs(self):
        if not os.path.exists(self.log_file):
            print(f"[WARNING] Log file {self.log_file} not found.")
            return []
        with open(self.log_file, "r", encoding="utf-8", errors="replace") as file:
            logs = [line.strip() for line in file.readlines() if line.strip()]
        return logs

    def detect_sql_injection(self, text):
        """Use regex patterns to determine if a given text is suspicious."""
        for pattern in SQL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def extract_features(self, logs):
        """Convert logs into features using TF-IDF."""
        vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer="char")
        features = vectorizer.fit_transform(logs)
        return features, vectorizer

    def load_or_train_model(self):
        if os.path.exists(self.model_file) and os.path.exists(self.vectorizer_file):
            self.model = joblib.load(self.model_file)
            self.vectorizer = joblib.load(self.vectorizer_file)
            print("[INFO] Model loaded successfully.")
        else:
            logs = self.load_logs()
            if logs:
                X, self.vectorizer = self.extract_features(logs)
                y = np.array([1 if self.detect_sql_injection(log) else 0 for log in logs])
                self.model = SGDClassifier(loss="hinge", max_iter=1000, tol=1e-3)
                self.model.fit(X, y)
                joblib.dump(self.model, self.model_file)
                joblib.dump(self.vectorizer, self.vectorizer_file)
                print("[INFO] Model trained and saved.")
            else:
                print("[ERROR] No logs available for training.")

    def predict(self, text):
        """Predict whether a text is a SQL injection attempt."""
        if not self.model or not self.vectorizer:
            raise Exception("Model is not loaded or trained.")
        X = self.vectorizer.transform([text])
        prediction = self.model.predict(X)
        confidence = max(self.model.decision_function(X))  # example of obtaining a score
        return prediction[0], confidence

    def log_detection(self, text, detected, confidence):
        """Log the detection result with metadata for future training."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = "Unknown"  # Extend this method to extract IP from text if needed.
        log_entry = f"[{timestamp}] IP: {ip}, Detected: {detected}, Confidence: {confidence:.2f}, Payload: {text}\n"
        with open("detection_log.log", "a") as f:
            f.write(log_entry)
        print(log_entry)
