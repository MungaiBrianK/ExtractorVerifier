import os
import dotenv

# Load environment variables from .env file
# Ensure your .env file is in the same directory as main.py
dotenv_load_success = dotenv.load_dotenv()
print(f"DEBUG: dotenv.load_dotenv() result: {dotenv_load_success}")

# --- Configuration for Azure Document Intelligence (read from environment) ---
AZURE_DI_ENDPOINT = os.environ.get("AZURE_DI_ENDPOINT", "YOUR_AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT_PLACEHOLDER")
AZURE_DI_API_KEY = os.environ.get("AZURE_DI_API_KEY", "YOUR_AZURE_DOCUMENT_INTELLIGENCE_API_KEY_PLACEHOLDER")

# --- CUSTOM MODEL ID (read from environment) ---
CUSTOM_MODEL_ID = os.environ.get("CUSTOM_MODEL_ID", "YOUR_CUSTOM_MODEL_ID_PLACEHOLDER")

# --- Configuration for ngrok (read from environment) ---
NGROK_AUTH_TOKEN = os.environ.get("NGROK_AUTH_TOKEN", "YOUR_NGROK_AUTH_TOKEN_PLACEHOLDER")
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))

# --- MongoDB Configuration (read from environment) ---
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/") # Default to local MongoDB
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "id_extractor_db")
MONGO_USERS_COLLECTION_NAME = os.environ.get("MONGO_USERS_COLLECTION", "users")
MONGO_ID_RECORDS_COLLECTION_NAME = os.environ.get("MONGO_IDRECORDS_COLLECTION", "id_records")
MONGO_VERIFICATION_LOGS_COLLECTION_NAME = os.environ.get("MONGO_VERIFICATION_LOGS_COLLECTION", "verification_logs") # NEW

# --- Flask Session Secret Key (REQUIRED for Flask-Login) ---
# IMPORTANT: Generate a strong, random key for production.
# You can generate one with: os.urandom(24).hex()
SECRET_KEY = os.environ.get("SECRET_KEY", "your_insecure_default_secret_key_change_this")

# Initial checks for credentials and configurations
if AZURE_DI_ENDPOINT == "YOUR_AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT_PLACEHOLDER" or \
   AZURE_DI_API_KEY == "YOUR_AZURE_DOCUMENT_INTELLIGENCE_API_KEY_PLACEHOLDER":
    print("WARNING: Azure Document Intelligence credentials are NOT correctly loaded from .env. Using placeholder defaults!")
    print("Please verify your .env file is in the same directory and contains correct AZURE_DI_ENDPOINT and AZURE_DI_API_KEY.")
else:
    print("INFO: Azure Document Intelligence credentials successfully detected from environment.")

if CUSTOM_MODEL_ID == "YOUR_CUSTOM_MODEL_ID_PLACEHOLDER":
    print("WARNING: CUSTOM_MODEL_ID is not set! Please ensure CUSTOM_MODEL_ID is defined in your .env file.")

if NGROK_AUTH_TOKEN == "YOUR_NGROK_AUTH_TOKEN_PLACEHOLDER":
    print("WARNING: NGROK_AUTH_TOKEN is not set! Please ensure NGROK_AUTH_TOKEN is defined in your .env file.")

if SECRET_KEY == "your_insecure_default_secret_key_change_this":
    print("CRITICAL WARNING: SECRET_KEY is using a default value. GENERATE A NEW ONE FOR PRODUCTION!")
    print("You can generate one using: import os; os.urandom(24).hex()")

if MONGO_URI == "mongodb://localhost:27017/":
    print("INFO: Using default local MongoDB URI. For cloud deployment, update MONGO_URI in .env.")
