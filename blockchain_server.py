from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import json
import os
from datetime import datetime, timezone
from filelock import FileLock
from config import (
    BLOCKCHAIN_FILE, BLOCKCHAIN_VERSION, RESET_BLOCKCHAIN,
    FLASK_DEBUG, FLASK_ENV, HOST, PORT, ALLOWED_ORIGINS,
    REQUIRED_THREAT_FIELDS, VALID_THREAT_TYPES
)

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
    """
    Represents a single block in the blockchain.
    
    Attributes:
        data: The data stored in the block
        previous_hash: Hash of the previous block
        timestamp: Creation timestamp of the block
        data_hash: Hash of the block's data
        hash: Hash of the entire block
    """
    def __init__(self, data, previous_hash, timestamp=None, data_hash=None, block_hash=None):
        self.data = data
        self.previous_hash = previous_hash
        self.timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.data_hash = data_hash or self._calculate_data_hash(data)
        self.hash = block_hash or Block.calculate_hash(self.data_hash, self.previous_hash, self.timestamp)

    @staticmethod
    def _calculate_data_hash(data):
        """Calculate the hash of the block's data."""
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def calculate_hash(data_hash, previous_hash, timestamp):
        """Calculate the hash of the entire block."""
        block_string = json.dumps({
            "data_hash": data_hash,
            "previous_hash": previous_hash,
            "timestamp": timestamp
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        """Convert block to dictionary format."""
        return {
            "data": self.data,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash,
            "hash": self.hash
        }


class Blockchain:
    """
    Manages the blockchain operations including block creation, validation, and persistence.
    """
    def __init__(self):
        self.lock_file = f"{BLOCKCHAIN_FILE}.lock"
        if RESET_BLOCKCHAIN and os.path.exists(BLOCKCHAIN_FILE):
            os.remove(BLOCKCHAIN_FILE)

        self.chain = self.load_chain()
        if not self.chain:
            self.chain = [self.create_genesis_block()]
            self.save_chain()

    @staticmethod
    def create_genesis_block():
        """Create the first block in the blockchain."""
        return Block({"type": "genesis", "message": "Zero-Day Sentinel Started"}, "0")

    def add_block(self, data):
        """
        Add a new block to the blockchain.
        
        Args:
            data: The data to be stored in the new block
            
        Returns:
            bool: True if block was added, False if it was a duplicate
        """
        data_hash = Block._calculate_data_hash(data)
        if any(block.data_hash == data_hash for block in self.chain):
            return False
            
        new_block = Block(data, self.chain[-1].hash)
        self.chain.append(new_block)
        self.save_chain()
        return True

    def save_chain(self):
        """Save the blockchain to disk with file locking."""
        with FileLock(self.lock_file):
            data = {
                "version": BLOCKCHAIN_VERSION,
                "chain": [b.to_dict() for b in self.chain]
            }
            with open(BLOCKCHAIN_FILE, "w") as f:
                json.dump(data, f, indent=4, sort_keys=True)

    def load_chain(self):
        """
        Load the blockchain from disk with validation.
        
        Returns:
            list: List of Block objects or None if loading fails
        """
        try:
            with FileLock(self.lock_file):
                if not os.path.exists(BLOCKCHAIN_FILE):
                    return None

                with open(BLOCKCHAIN_FILE, "r") as f:
                    file_data = json.load(f)

                if isinstance(file_data, list):
                    print("Error: Blockchain file in old format (list). Resetting to genesis block.")
                    return None

                file_version = file_data.get("version", "0.0")
                if file_version != BLOCKCHAIN_VERSION:
                    print(f"Error: Incompatible version {file_version}. Resetting blockchain.")
                    return None

                return self._validate_and_load_blocks(file_data["chain"])
        except json.JSONDecodeError:
            print("Error: Corrupted blockchain file! Resetting to genesis block.")
            return [self.create_genesis_block()]
        except Exception as e:
            print(f"Error loading blockchain: {str(e)}")
            return None

    def _validate_and_load_blocks(self, blocks_data):
        """Validate and load blocks from data."""
        chain = []
        for i, block in enumerate(blocks_data):
            try:
                b = Block(
                    block["data"],
                    block["previous_hash"],
                    block["timestamp"],
                    block["data_hash"],
                    block["hash"]
                )
                
                if Block.calculate_hash(b.data_hash, b.previous_hash, b.timestamp) != block["hash"]:
                    print(f"Error: Tampering detected at block {i}! Recovering up to block {i-1}.")
                    return chain[:i] if i > 0 else [self.create_genesis_block()]
                    
                chain.append(b)
            except KeyError as e:
                print(f"Error: Invalid block format (missing key: {e})! Resetting blockchain.")
                return None
        return chain

    def verify_chain(self):
        """
        Verify the integrity of the entire blockchain.
        
        Returns:
            tuple: (bool, str) - (is_valid, message)
        """
        try:
            with FileLock(self.lock_file):
                with open(BLOCKCHAIN_FILE, "r") as file:
                    blockchain_data = json.load(file)
                    blockchain = blockchain_data["chain"]

                for i in range(1, len(blockchain)):
                    if not self._verify_block(blockchain[i], blockchain[i-1], i):
                        return False, f"Invalid block at index {i}"
                        
                return True, "Blockchain is valid!"
        except Exception as e:
            return False, f"Error verifying chain: {str(e)}"

    def _verify_block(self, current_block, previous_block, index):
        """Verify a single block and its connection to the previous block."""
        # Verify previous block
        prev_data_hash = Block._calculate_data_hash(previous_block["data"])
        if prev_data_hash != previous_block["data_hash"]:
            return False
            
        prev_hash = Block.calculate_hash(
            prev_data_hash,
            previous_block["previous_hash"],
            previous_block["timestamp"]
        )
        if prev_hash != previous_block["hash"]:
            return False

        # Verify current block's connection
        if current_block["previous_hash"] != previous_block["hash"]:
            return False

        # Verify current block
        curr_data_hash = Block._calculate_data_hash(current_block["data"])
        if curr_data_hash != current_block["data_hash"]:
            return False
            
        curr_hash = Block.calculate_hash(
            curr_data_hash,
            current_block["previous_hash"],
            current_block["timestamp"]
        )
        return curr_hash == current_block["hash"]

    def get_chain_length(self):
        """Get the current length of the blockchain."""
        return len(self.chain)

# ------------------------------
# Flask Backend API
# ------------------------------

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

blockchain = Blockchain()

def validate_threat_data(data):
    """
    Validate the threat data structure.
    
    Args:
        data: The threat data to validate
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Threat data must be a JSON object"
        
    for field in REQUIRED_THREAT_FIELDS:
        if field not in data:
            return False, f"Missing required field: {field}"
            
    if data["type"] not in VALID_THREAT_TYPES:
        return False, f"Invalid threat type. Must be one of: {', '.join(VALID_THREAT_TYPES)}"
        
    if not isinstance(data["details"], dict):
        return False, "Details must be a JSON object"
        
    return True, ""

@app.route("/", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "version": BLOCKCHAIN_VERSION})

@app.route("/chain", methods=["GET"])
@limiter.limit("10 per second")  # Rate limit for chain endpoint
def get_chain():
    """Get the current state of the blockchain."""
    return jsonify({
        "length": len(blockchain.chain),
        "chain": [b.to_dict() for b in blockchain.chain]
    })

@app.route("/threat", methods=["POST"])
def add_threat():
    """
    Add a new threat to the blockchain.
    
    Expected JSON format:
    {
        "type": "suspicious_login",
        "details": {
            "ip": "192.168.1.10",
            "message": "Unusual login activity"
        }
    }
    """
    try:
        threat_data = request.get_json()
        if not threat_data:
            return jsonify({"error": "Invalid threat data"}), 400

        is_valid, error_message = validate_threat_data(threat_data)
        if not is_valid:
            return jsonify({"error": error_message}), 400

        added = blockchain.add_block(threat_data)
        if not added:
            return jsonify({"message": "Duplicate threat data, block not added"}), 409

        return jsonify({
            "message": "Threat added successfully!",
            "new_block": blockchain.chain[-1].to_dict()
        })
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/verify", methods=["GET"])
def verify():
    """Verify the integrity of the blockchain."""
    valid, msg = blockchain.verify_chain()
    if valid:
        return jsonify({"message": msg})
    else:
        return jsonify({"error": msg}), 400
    
@app.route("/reset", methods=["POST"])
def reset_blockchain():
    """Reset the blockchain to its initial state."""
    try:
        blockchain.chain = [blockchain.create_genesis_block()]
        blockchain.save_chain()
        return jsonify({
            "message": "Blockchain reset successfully!",
            "chain": [b.to_dict() for b in blockchain.chain]
        })
    except Exception as e:
        return jsonify({"error": f"Failed to reset blockchain: {str(e)}"}), 500

# ------------------------------
# Main Execution
# ------------------------------

if __name__ == "__main__":
    try:
        app.run(host=HOST, port=PORT, debug=FLASK_DEBUG)
    except Exception as e:
        print(f"Error starting server: {str(e)}")
        raise
