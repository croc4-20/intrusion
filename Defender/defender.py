# defender.py
import os
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from threading import Thread
import queue
import time

class AIDefender:
    def __init__(self, model_file='packet_model.pkl', vectorizer_file='vectorizer.pkl'):
        self.model_file = model_file
        self.vectorizer_file = vectorizer_file
        self.model = None
        self.vectorizer = None
        self.packet_queue = queue.Queue()
        self.is_running = False
        self.load_or_train_model()
        
        # Statistics for learning
        self.false_positives = 0
        self.false_negatives = 0
        self.total_packets = 0
    
    def load_or_train_model(self):
        """Load existing model or train a new one"""
        if os.path.exists(self.model_file) and os.path.exists(self.vectorizer_file):
            self.model = joblib.load(self.model_file)
            self.vectorizer = joblib.load(self.vectorizer_file)
            print("[INFO] Model loaded successfully.")
        else:
            self.train_model()

    def train_model(self):
        """Train initial model with sample data"""
        sample_data = ["normal packet content", "malicious packet content"]
        labels = [0, 1]  # 0 for normal, 1 for malicious
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer="char")
        X = self.vectorizer.fit_transform(sample_data)
        self.model = SGDClassifier(loss="hinge", max_iter=1000, tol=1e-3)
        self.model.fit(X, labels)
        joblib.dump(self.model, self.model_file)
        joblib.dump(self.vectorizer, self.vectorizer_file)
        print("[INFO] Model trained and saved.")

    def predict(self, packet_content):
        """Predict if a packet is malicious"""
        if not self.model or not self.vectorizer:
            raise Exception("Model is not loaded or trained.")
        X = self.vectorizer.transform([packet_content])
        prediction = self.model.predict(X)
        confidence = max(self.model.decision_function(X))
        return prediction[0], confidence

    def start(self):
        """Start the defender in a separate thread"""
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
        """Stop the defender"""
        self.is_running = False
        
    def _sniff_packets(self):
        """Sniff packets and add them to queue"""
        sniff(filter="tcp", prn=lambda x: self.packet_queue.put(x))
        
    def _process_packets(self):
        """Process packets from queue"""
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1)
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    self._handle_packet(packet)
            except queue.Empty:
                continue
                
    def _handle_packet(self, packet):
        """Handle a single packet"""
        packet_content = str(packet[TCP].payload)
        prediction, confidence = self.predict(packet_content)
        self.total_packets += 1
        
        # Record features for learning
        features = {
            'size': len(packet_content),
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'flags': packet[TCP].flags
        }
        
        if prediction == 1:
            print(f"Blocked malicious packet with confidence {confidence}")
            # Here you would implement actual blocking logic
            # For now we just log it
            self.log_detection(packet_content, features, True, confidence)
        else:
            print(f"Allowed normal packet with confidence {confidence}")
            self.log_detection(packet_content, features, False, confidence)
            
    def log_detection(self, content, features, is_blocked, confidence):
        """Log packet details for learning"""
        # TODO: Implement logging to file/database for further training
        pass
        
    def retrain_model(self, new_data, new_labels):
        """Retrain the model with new data"""
        if not self.vectorizer:
            self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer="char")
            
        # Combine old and new data
        X = self.vectorizer.fit_transform(new_data)
        self.model = SGDClassifier(loss="hinge", max_iter=1000, tol=1e-3)
        self.model.partial_fit(X, new_labels, classes=[0, 1])
        
        # Save updated model
        joblib.dump(self.model, self.model_file)
        joblib.dump(self.vectorizer, self.vectorizer_file)
        print("[INFO] Model retrained and saved.")

# server.py
from flask import Flask, request, jsonify

app = Flask(__name__)
defender = AIDefender()

@app.route('/start', methods=['POST'])
def start_defender():
    defender.start()
    return jsonify({"status": "Defender started"})

@app.route('/stop', methods=['POST'])
def stop_defender():
    defender.stop()
    return jsonify({"status": "Defender stopped"})

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify({
        "total_packets": defender.total_packets,
        "false_positives": defender.false_positives,
        "false_negatives": defender.false_negatives
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)