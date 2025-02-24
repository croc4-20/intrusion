import os
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP
from threading import Thread
import queue
import time
import pandas as pd
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import SGDClassifier

class AIDefender:
    def __init__(self, model_file='unsw_model.pkl'):
        self.model_file = model_file
        self.model = None
        self.feature_columns = None  # List of feature names used for training
        self.packet_queue = queue.Queue()
        self.is_running = False

        # Statistics for learning
        self.false_positives = 0
        self.false_negatives = 0
        self.total_packets = 0

        self.load_or_train_model()

    def load_or_train_model(self):
        """Load the model if it exists; otherwise, train a new one using the UNSW-NB15 dataset."""
        if os.path.exists(self.model_file):
            # We saved both the model and the feature columns as a tuple.
            self.model, self.feature_columns = joblib.load(self.model_file)
            print("[INFO] Model loaded successfully.")
        else:
            self.train_model()

    def train_model(self):
        """
        Train the model using the UNSW-NB15 training CSV.
        This method:
          1. Loads the CSV.
          2. Drops non-relevant columns (IP addresses, attack_cat, etc.).
          3. Converts all features to numeric.
          4. Splits features (X) from the binary label (y).
          5. Builds a pipeline with StandardScaler and SGDClassifier.
          6. Saves the trained model along with the feature column order.
        """
        csv_path = "UNSW-NB15_Training-set.csv"  # Adjust path as needed
        print(f"[INFO] Loading training data from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        # Drop the 'attack_cat' column (and any other non-numeric or irrelevant columns)
        drop_cols = ['attack_cat', 'srcip', 'dstip', 'id', 'Unnamed: 0']
        df = df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore')
        
        # Ensure the label column exists (assumed to be named 'label')
        if 'label' not in df.columns:
            raise ValueError("CSV file must contain a 'label' column for binary classification.")
        
        # Separate features and label
        y = df['label']
        X = df.drop(columns=['label'])
        
        # Convert all columns to numeric (if not already) and fill missing values
        X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # Save the feature column order for use during prediction
        self.feature_columns = X.columns.tolist()
        print(f"[INFO] Using features: {self.feature_columns}")
        
        # Build the pipeline: scaling + linear classifier
        pipeline = make_pipeline(
            StandardScaler(),
            SGDClassifier(loss="hinge", max_iter=1000, tol=1e-3, random_state=42)
        )
        
        # Fit the model
        pipeline.fit(X, y)
        self.model = pipeline
        
        # Save both the model and the feature_columns for consistency during live prediction
        joblib.dump((self.model, self.feature_columns), self.model_file)
        print("[INFO] Model trained on UNSW-NB15 data and saved.")

    def predict(self, features_dict):
        """
        Predict if a packet is malicious.
        `features_dict` should be a dictionary with keys matching self.feature_columns.
        Returns (prediction, confidence).
        """
        # Create a DataFrame from the features_dict with the proper column order
        X_live = pd.DataFrame([features_dict], columns=self.feature_columns)
        # Fill any missing values
        X_live = X_live.fillna(0)
        
        # Use the model's decision_function and predict methods
        decision = self.model.decision_function(X_live)
        pred = self.model.predict(X_live)
        confidence = float(decision[0])
        return pred[0], confidence

    def start(self):
        """Start packet sniffing and processing in separate threads."""
        self.is_running = True
        
        # Start packet processing thread
        self.process_thread = Thread(target=self._process_packets)
        self.process_thread.daemon = True
        self.process_thread.start()
        
        # Start packet sniffing thread
        self.sniff_thread = Thread(target=self._sniff_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop(self):
        """Stop the defender."""
        self.is_running = False

    def _sniff_packets(self):
        """Sniff packets and add them to the queue."""
        sniff(filter="tcp", prn=lambda x: self.packet_queue.put(x))

    def _process_packets(self):
        """Process packets from the queue."""
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1)
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    self._handle_packet(packet)
            except queue.Empty:
                continue

    def _handle_packet(self, packet):
        """
        Extract numeric features from a live packet and predict if it is malicious.
        NOTE: This is a simplified example. In a production system, you would extract
        the same features as used in the training dataset.
        """
        # Example: extract a few features that match UNSW-NB15 training features.
        # You should expand this to extract all features used during training.
        # For demonstration, we assume the following keys were used:
        # 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', etc.
        # Here, we simulate some values based on available packet info.
        # In reality, you might compute these from the packet contents.
        features_dict = {
            'sbytes': 0,  # Placeholder: bytes sent by source (needs actual extraction)
            'dbytes': 0,  # Placeholder: bytes sent by destination
            'rate': 0,    # Placeholder: connection rate
            'sttl': 64,   # Common default TTL value for source
            'dttl': 64,   # Common default TTL value for destination
            'sload': 0,
            'dload': 0,
            'sloss': 0,
            'dloss': 0,
            'sinpkt': 0,
            'dinpkt': 0,
            'sjit': 0,
            'djit': 0,
            'swin': 0,
            'stcpb': packet[TCP].sport,
            'dtcpb': packet[TCP].dport,
            'dwin': 0,
            'tcprtt': 0,
            'synack': 0,
            'ackdat': 0,
            'smean': 0,
            'dmean': 0,
            'trans_depth': 0,
            'response_body_len': 0,
            'ct_srv_src': 0,
            'ct_state_ttl': 0,
            'ct_dst_ltm': 0,
            'ct_src_dport_ltm': 0,
            'ct_dst_sport_ltm': 0,
            'ct_dst_src_ltm': 0,
            'is_ftp_login': 0,
            'ct_ftp_cmd': 0,
            'ct_flw_http_mthd': 0,
            'ct_src_ltm': 0,
            'ct_srv_dst': 0,
            'is_sm_ips_ports': 0
        }
        # You may need to adjust or compute these features from packet data.

        pred, confidence = self.predict(features_dict)
        self.total_packets += 1

        if pred == 1:
            print(f"[ALERT] Blocked malicious packet | Confidence: {confidence}")
            # Implement further blocking logic if desired
            self.log_detection(features_dict, True, confidence)
        else:
            print(f"Allowed normal packet | Confidence: {confidence}")
            self.log_detection(features_dict, False, confidence)

    def log_detection(self, features, is_blocked, confidence):
        """Log packet details for further analysis (to be implemented)."""
        # For example, write to a CSV or database for later retraining.
        pass
