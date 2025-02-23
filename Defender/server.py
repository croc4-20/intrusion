# server.py
from flask import Flask, request, jsonify
from defender import AIDefender
from defender_rl import DefenderRL

app = Flask(__name__)
defender = AIDefender()
action_space = ["block_ip", "rate_limit", "allow"]
state_space = ["normal", "under_attack"]
defender_rl = DefenderRL(action_space, state_space)

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

@app.route('/detect', methods=['POST'])
def detect():
    data = request.get_json()
    if not data or 'payload' not in data:
        return jsonify({"error": "Payload not provided"}), 400
    
    payload = data['payload']
    state = "normal"  # Initial state, can be updated based on payload analysis
    action = defender_rl.choose_action(state)
    
    # Simulate the environment's response to the action
    reward, next_state = simulate_environment(state, action)
    defender_rl.learn(state, action, reward, next_state)
    state = next_state
    
    result, confidence = defender.predict(payload)
    defender.log_detection(payload, bool(result), confidence)
    return jsonify({
        "detected": bool(result), 
        "confidence": confidence, 
        "action": action
    })

def simulate_environment(state, action):
    # Simulate the environment's response to the action
    reward = 1 if action == "allow" else -1
    next_state = "normal" if action == "allow" else "under_attack"
    return reward, next_state

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
