from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime
import re # Import regex module for ID number normalization

from config import MONGO_URI, MONGO_DB_NAME, MONGO_USERS_COLLECTION_NAME, \
                   MONGO_ID_RECORDS_COLLECTION_NAME, MONGO_VERIFICATION_LOGS_COLLECTION_NAME

class MongoService:
    def __init__(self):
        self.client = None
        self.db = None
        self.users_collection = None
        self.id_records_collection = None
        self.verification_logs_collection = None
        self._connect()

    def _connect(self):
        """Establishes connection to MongoDB."""
        try:
            self.client = MongoClient(MONGO_URI)
            self.client.admin.command('ping') # Test connection
            self.db = self.client[MONGO_DB_NAME]
            self.users_collection = self.db[MONGO_USERS_COLLECTION_NAME]
            self.id_records_collection = self.db[MONGO_ID_RECORDS_COLLECTION_NAME]
            self.verification_logs_collection = self.db[MONGO_VERIFICATION_LOGS_COLLECTION_NAME]
            print("INFO: MongoDB connection successful.")

            # Ensure unique index for username
            try:
                self.users_collection.create_index("username", unique=True)
                print("INFO: Unique index on 'username' ensured for users collection.")
            except Exception as e:
                print(f"WARNING: Could not create unique index on 'username': {e}")

            # Ensure unique index for idNumber and serialNumber combined
            try:
                self.id_records_collection.create_index([("idNumber", 1), ("serialNumber", 1)], unique=True)
                print("INFO: Compound unique index on 'idNumber' and 'serialNumber' ensured for id_records collection.")
            except Exception as e:
                print(f"WARNING: Could not create compound unique index on 'idNumber' and 'serialNumber': {e}")


        except ConnectionFailure as e:
            print(f"ERROR: MongoDB connection failed: {e}")
            self.client = None # Ensure client is None if connection fails
        except Exception as e:
            print(f"ERROR: An unexpected error occurred during MongoDB connection: {e}")
            self.client = None

    def _normalize_id_number(self, id_number):
        """Normalizes ID numbers by removing non-alphanumeric characters and converting to uppercase."""
        if id_number:
            return re.sub(r'[^a-zA-Z0-9]', '', str(id_number)).upper() # Ensure input is string for re.sub
        return ""

    def _serialize_mongo_doc(self, doc):
        """
        Recursively converts ObjectId and datetime objects in a MongoDB document
        (or dictionary) to strings for JSON serialization.
        Handles nested dictionaries and lists.
        """
        if isinstance(doc, dict):
            return {k: self._serialize_mongo_doc(v) for k, v in doc.items()}
        elif isinstance(doc, list):
            return [self._serialize_mongo_doc(elem) for elem in doc]
        elif isinstance(doc, ObjectId):
            return str(doc)
        elif isinstance(doc, datetime):
            return doc.isoformat()
        return doc

    # --- User Management ---
    def create_user(self, username, email, password, role_name='user', admin_user_id=None):
        """
        Creates a new user with a hashed password.
        Returns the new user's ID and a success/error message.
        """
        if self.users_collection is None:
            return None, "Database not connected."

        # Basic validation
        if not username or not email or not password:
            return None, "Username, email, and password cannot be empty."
        if len(password) < 8:
            return None, "Password must be at least 8 characters long."
        if not re.search(r'[A-Z]', password):
            return None, "Password must contain at least one uppercase letter."
        if not re.search(r'[a-z]', password):
            return None, "Password must contain at least one lowercase letter."
        if not re.search(r'\d', password):
            return None, "Password must contain at least one digit."
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return None, "Password must contain at least one special character."

        hashed_password = generate_password_hash(password)
        roles = [1] if role_name == 'admin' else [0]
        
        try:
            user_data = {
                "username": username,
                "email": email,
                "password_hash": hashed_password,
                "roles": roles,
                "is_active": True,
                "created_at": datetime.now(),
                "last_login": None,
                "last_updated_at": datetime.now(),
                "last_updated_by_admin_id": ObjectId(admin_user_id) if admin_user_id else None
            }
            result = self.users_collection.insert_one(user_data)
            return str(result.inserted_id), "User registered successfully."
        except OperationFailure as e:
            if e.code == 11000: # Duplicate key error
                return None, "Username or email already exists."
            return None, f"Database error: {e.details.get('errmsg', str(e))}"
        except Exception as e:
            return None, f"An unexpected error occurred: {str(e)}"

    def get_user_by_username(self, username):
        """Retrieves a user by username."""
        if self.users_collection is None: return None
        return self.users_collection.find_one({"username": username})

    def get_user_by_id(self, user_id):
        """Retrieves a user by ID."""
        if self.users_collection is None: return None
        try:
            return self.users_collection.find_one({"_id": ObjectId(user_id)})
        except Exception:
            return None

    def verify_password(self, username, password):
        """Verifies a user's password and updates last_login."""
        if self.users_collection is None: return None
        user = self.get_user_by_username(username)
        if user and user.get('is_active', False):
            password_hash = user.get('password_hash')
            if password_hash and check_password_hash(password_hash, password):
                self.users_collection.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"last_login": datetime.now()}}
                )
                return user
        return None

    def update_user(self, user_id, username, email, new_password=None, role_name=None, is_active=None, admin_user_id=None):
        """Updates user details."""
        if self.users_collection is None:
            return False, "Database not connected."
        
        try:
            obj_user_id = ObjectId(user_id)
            update_fields = {
                "last_updated_at": datetime.now(),
                "last_updated_by_admin_id": ObjectId(admin_user_id) if admin_user_id else None
            }

            if new_password:
                if len(new_password) < 8:
                    return False, "New password must be at least 8 characters long."
                if not re.search(r'[A-Z]', new_password):
                    return False, "New password must contain at least one uppercase letter."
                if not re.search(r'[a-z]', new_password):
                    return False, "New password must contain at least one lowercase letter."
                if not re.search(r'\d', new_password):
                    return False, "New password must contain at least one digit."
                if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
                    return False, "New password must contain at least one special character."
                update_fields["password_hash"] = generate_password_hash(new_password)

            if username:
                update_fields["username"] = username
            if email:
                update_fields["email"] = email
            if role_name:
                update_fields["roles"] = [1] if role_name == 'admin' else [0]
            if is_active is not None:
                update_fields["is_active"] = is_active

            result = self.users_collection.update_one({"_id": obj_user_id}, {"$set": update_fields})
            if result.matched_count == 0:
                return False, "User not found."
            return True, "User updated successfully."
        except OperationFailure as e:
            if e.code == 11000: # Duplicate key error
                return False, "Username or email already exists."
            return False, f"Database error: {e.details.get('errmsg', str(e))}"
        except Exception as e:
            return False, f"An unexpected error occurred: {str(e)}"

    def delete_user(self, user_id, admin_user_id=None):
        """Deletes a user."""
        if self.users_collection is None:
            return False, "Database not connected."
        try:
            obj_user_id = ObjectId(user_id)
            result = self.users_collection.delete_one({"_id": obj_user_id})
            if result.deleted_count == 0:
                return False, "User not found."
            return True, "User deleted successfully."
        except Exception as e:
            return False, f"An unexpected error occurred: {str(e)}"

    # --- ID Record Management ---
    def add_id_record(self, id_data):
        """Adds a new ID record to the database."""
        if self.id_records_collection is None: return None
        try:
            # Normalize ID and Serial Numbers before saving - ensure they are stored as strings
            if 'idNumber' in id_data:
                id_data['idNumber'] = self._normalize_id_number(id_data['idNumber'])
            if 'serialNumber' in id_data:
                id_data['serialNumber'] = self._normalize_id_number(id_data['serialNumber'])

            id_data['created_at'] = datetime.now()
            result = self.id_records_collection.insert_one(id_data)
            return str(result.inserted_id)
        except OperationFailure as e:
            if e.code == 11000: # Duplicate key error
                return "Duplicate ID Number and Serial Number combination."
            return f"Database error: {e.details.get('errmsg', str(e))}"
        except Exception as e:
            return str(e)

    def get_id_record_by_numbers(self, id_number, serial_number):
        """
        Retrieves an ID record by normalized ID number and serial number.
        Tries to match both string and integer types for backward compatibility.
        """
        if self.id_records_collection is None: return None
        
        normalized_id_str = self._normalize_id_number(id_number)
        normalized_serial_str = self._normalize_id_number(serial_number)
        
        # 1. Try matching with string types (consistent with current add_id_record)
        record = self.id_records_collection.find_one({
            "idNumber": normalized_id_str,
            "serialNumber": normalized_serial_str
        })

        # 2. If not found, try matching with integer types for backward compatibility
        if record is None:
            try:
                int_id = int(normalized_id_str)
                int_serial = int(normalized_serial_str)
                record = self.id_records_collection.find_one({
                    "idNumber": int_id,
                    "serialNumber": int_serial
                })
            except ValueError:
                # If conversion to int fails, it means the normalized string was not purely numeric
                pass
            except Exception as e:
                print(f"DEBUG: Error trying integer lookup for ID record: {e}")


        return self._serialize_mongo_doc(record) if record else None


    # --- Verification Log Management ---
    def log_verification_job(self, user_id, username, id_number, status, timestamp, extracted_data, verified_data=None, error_message=None, manual_review_recommended=False, confidence=None):
        """
        Logs an ID verification job.
        confidence: Dictionary containing confidence scores, including 'Overall Confidence'.
        """
        if self.verification_logs_collection is None: return

        log_entry = {
            "user_id": str(user_id),
            "username": username,
            "id_number_attempted": id_number,
            "status": status,
            "timestamp": timestamp,
            "extracted_data": self._serialize_mongo_doc(extracted_data), # This now includes 'Overall Confidence'
            "verified_data": self._serialize_mongo_doc(verified_data) if verified_data else None,
            "error_message": error_message,
            "manual_review_recommended": manual_review_recommended,
            "confidence": self._serialize_mongo_doc(confidence) if confidence else {} # Still store raw confidence for completeness
        }
        try:
            self.verification_logs_collection.insert_one(log_entry)
            print(f"INFO: Verification job logged successfully for user {username}, ID: {id_number}")
        except Exception as e:
            print(f"ERROR: Failed to log verification job: {e}")

# Instantiate the service globally
mongo_service = MongoService()
