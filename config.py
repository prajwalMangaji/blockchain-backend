import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Blockchain Configuration
BLOCKCHAIN_FILE = "blockchain.json"
BLOCKCHAIN_VERSION = "1.0"
RESET_BLOCKCHAIN = False

# Flask Configuration
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
FLASK_ENV = os.getenv("FLASK_ENV", "production")
HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", 8080))

# CORS Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# Threat Data Validation
REQUIRED_THREAT_FIELDS = ["type", "details"]
VALID_THREAT_TYPES = ["suspicious_login", "malware_detected", "unauthorized_access", "data_breach"] 