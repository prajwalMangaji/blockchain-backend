from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import json
import os
from datetime import datetime, timezone

# ------------------------------
# Blockchain Code
# ------------------------------

import hashlib
import json
from datetime import datetime, timezone

import hashlib
import json
from datetime import datetime, timezone

class Block:
    def __init__(self, data, previous_hash, timestamp=None, data_hash=None, block_hash=None):
        self.data = data
        self.previous_hash = previous_hash
        self.timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.data_hash = data_hash or hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        self.hash = block_hash or Block.calculate_hash(self.data_hash, self.previous_hash, self.timestamp)

    @staticmethod
    def calculate_hash(data_hash, previous_hash, timestamp):
        block_string = json.dumps({
            "data_hash": data_hash,
            "previous_hash": previous_hash,
            "timestamp": timestamp
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "data": self.data,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash,
            "hash": self.hash
        }


class Blockchain:
    RESET_BLOCKCHAIN = False
    FILE_NAME = "blockchain.json"
    VERSION = "1.0"

    def __init__(self):
        if self.RESET_BLOCKCHAIN and os.path.exists(self.FILE_NAME):
            os.remove(self.FILE_NAME)

        self.chain = self.load_chain()
        if not self.chain:
            self.chain = [self.create_genesis_block()]
            self.save_chain()

    @staticmethod
    def create_genesis_block():
        return Block({"type": "genesis", "message": "Zero-Day Sentinel Started"}, "0")

    def add_block(self, data):
        data_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        # Prevent duplicate threat data from being added
        if any(block.data_hash == data_hash for block in self.chain):
            print(f"Skipping duplicate block with data_hash: {data_hash}")
            return False
        new_block = Block(data, self.chain[-1].hash)
        self.chain.append(new_block)
        self.save_chain()
        return True

    def save_chain(self):
        data = {
            "version": self.VERSION,
            "chain": [b.to_dict() for b in self.chain]
        }
        with open(self.FILE_NAME, "w") as f:
            json.dump(data, f, indent=4, sort_keys=True)

    def load_chain(self):
        try:
            with open(self.FILE_NAME, "r") as f:
                file_data = json.load(f)

                if isinstance(file_data, list):
                    print("🚨 Blockchain file in old format (list). Resetting to genesis block.")
                    return None

                file_version = file_data.get("version", "0.0")
                if file_version != self.VERSION:
                    print(f"🚨 Incompatible version {file_version}. Resetting blockchain.")
                    return None

                data = file_data["chain"]
                chain = []
                for i, block in enumerate(data):
                    data_hash = block.get("data_hash", hashlib.sha256(json.dumps(block["data"], sort_keys=True).encode()).hexdigest())
                    b = Block(block["data"], block["previous_hash"], block["timestamp"], block["data_hash"], block["hash"])
                    if Block.calculate_hash(b.data_hash, b.previous_hash, b.timestamp) != block["hash"]:
                        print(f"🚨 Tampering detected at block {i}! Recovering up to block {i-1}.")
                        return chain[:i] if i > 0 else [Blockchain.create_genesis_block()]
                    chain.append(b)
                return chain
        except FileNotFoundError:
            return None
        except json.JSONDecodeError:
            print("🚨 Corrupted blockchain file! Resetting to genesis block.")
            return [self.create_genesis_block()]
        except KeyError as e:
            print(f"🚨 Invalid blockchain file format (missing key: {e})! Resetting blockchain.")
            return None

    def verify_chain(self):
        with open("blockchain.json", "r") as file:
            blockchain_data = json.load(file)
            blockchain = blockchain_data["chain"]

        for i in range(1, len(blockchain)):
            # Verify previous block first
            prev_block = blockchain[i - 1]
            # Recalculate data_hash from the actual data
            computed_prev_data_hash = hashlib.sha256(json.dumps(prev_block["data"], sort_keys=True).encode()).hexdigest()
            if computed_prev_data_hash != prev_block["data_hash"]:
                return False, f"Data tampering detected in block {i-1}"
            # Recalculate the previous block's overall hash using computed data_hash, previous_hash, and timestamp
            recalculated_prev_hash = Block.calculate_hash(
                computed_prev_data_hash,
                prev_block["previous_hash"],
                prev_block["timestamp"]
            )
            # Check if the stored hash of previous block matches the recalculated one
            if prev_block["hash"] != recalculated_prev_hash:
                return False, f"Invalid hash in block {i-1}"

            # Now, verify the current block's "previous_hash" field
            if blockchain[i]["previous_hash"] != prev_block["hash"]:
                return False, f"Invalid previous hash at block {i}"

            # Verify current block data and hash
            curr_block = blockchain[i]
            computed_curr_data_hash = hashlib.sha256(json.dumps(curr_block["data"], sort_keys=True).encode()).hexdigest()
            if computed_curr_data_hash != curr_block["data_hash"]:
                return False, f"Data tampering detected in block {i}"
            recalculated_curr_hash = Block.calculate_hash(
                computed_curr_data_hash,
                curr_block["previous_hash"],
                curr_block["timestamp"]
            )
            if curr_block["hash"] != recalculated_curr_hash:
                return False, f"Invalid hash at block {i}"

        return True, "Blockchain is valid!"

    def get_chain_length(self):
        return len(self.chain)

# ------------------------------
# Flask Backend API
# ------------------------------

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
blockchain = Blockchain()

@app.route("/chain", methods=["GET"])
def get_chain():
    return jsonify({"length": len(blockchain.chain), "chain": [b.to_dict() for b in blockchain.chain]})

@app.route("/threat", methods=["POST"])
def add_threat():
    """
    Receives threat data from the ML model (or for demo, from manual POST requests).
    Expected JSON format:
    {
        "type": "suspicious_login",
        "details": {"ip": "192.168.1.10", "message": "Unusual login activity"}
    }
    """
    threat_data = request.get_json()
    if not threat_data:
        return jsonify({"error": "Invalid threat data"}), 400

    added = blockchain.add_block(threat_data)
    if not added:
        return jsonify({"message": "Duplicate threat data, block not added"}), 409

    return jsonify({"message": "Threat added successfully!", "new_block": blockchain.chain[-1].to_dict()})

@app.route("/verify", methods=["GET"])
def verify():
    valid, msg = blockchain.verify_chain()
    if valid:
        return jsonify({"message": msg})
    else:
        return jsonify({"error": msg}), 400
    
@app.route("/reset", methods=["POST"])
def reset_blockchain():
    """
    Resets the blockchain by clearing all blocks and creating a new genesis block.
    """
    blockchain.chain = [blockchain.create_genesis_block()]
    blockchain.save_chain()
    return jsonify({"message": "Blockchain reset successfully!", "chain": [b.to_dict() for b in blockchain.chain]})

# ------------------------------
# Main Execution
# ------------------------------

if __name__ == "__main__":
    # For demo, you can add a test threat on startup (optional)
    # blockchain.add_block({"type": "test_threat", "details": {"ip": "1.2.3.4", "message": "Demo threat"}})
    
    app.run(host="0.0.0.0", port=8080, debug=True)
