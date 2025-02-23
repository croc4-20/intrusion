from flask import Flask, request, jsonify
from detection import Defender

app = Flask(__name__)
defender = Defender()

@app.route('/detect', methods=['POST'])
def detect():
    data = request.get_json()
    if not data or 'payload' not in data:
        return jsonify({"error": "Payload not provided"}), 400
    payload = data['payload']
    result, confidence = defender.predict(payload)
    defender.log_detection(payload, bool(result), confidence)
    return jsonify({"detected": bool(result), "confidence": confidence})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
