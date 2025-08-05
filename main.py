import os
import io
import base64
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from threading import Thread # for potential background tasks if any
import time # for potential delays
from datetime import datetime
import csv # For CSV export
from io import StringIO # For CSV export

# Importing custom modules
from config import AZURE_DI_ENDPOINT, AZURE_DI_API_KEY, CUSTOM_MODEL_ID, FLASK_PORT, SECRET_KEY 
from azure_di_service import AzureDocumentIntelligenceService
from mongo_service import mongo_service

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth' # Redirecting to the /auth route for login

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data.get('email')
        self.roles = user_data.get('roles', [0])
        self.role = 'admin' if 1 in self.roles else 'user'
        self.created_at = user_data.get('created_at')
        self.last_login = user_data.get('last_login')
        self._user_data = user_data
        self.last_updated_at = user_data.get('last_updated_at')
        self.last_updated_by_admin_id = user_data.get('last_updated_by_admin_id')

    def get_id(self):
        return self.id

    @property
    def is_active(self):
        return self._user_data.get('is_active', True)

    def is_admin(self):
        return 1 in self.roles

@login_manager.user_loader
def load_user(user_id):
    # importing mongo_service to avoid circular dependencies with mongo_service
    from mongo_service import mongo_service
    user_data = mongo_service.get_user_by_id(user_id)
    if user_data:
        return User(user_data)
    return None

# --- Azure Document Intelligence Service Initialization ---
azure_di_service = None
if AZURE_DI_ENDPOINT and AZURE_DI_API_KEY:
    try:
        azure_di_service = AzureDocumentIntelligenceService(AZURE_DI_ENDPOINT, AZURE_DI_API_KEY, CUSTOM_MODEL_ID)
        print("INFO: Azure Document Intelligence service client successfully initialized.")
    except ValueError as e:
        print(f"ERROR: Failed to initialize Azure Document Intelligence service: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during Azure DI service initialization: {e}")
else:
    print("ERROR: Azure Document Intelligence credentials (AZURE_DI_ENDPOINT or AZURE_DI_API_KEY) are not set. Extraction will not work.")


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth')
def auth():
    """Route to serve the React authentication application."""
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    """API endpoint for user registration from React frontend."""
    if current_user.is_authenticated:
        return jsonify({'message': 'You are already logged in.'}), 200 

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role_to_assign = 'user'

    if not username or not email or not password:
        return jsonify({'message': 'Username, email, and password are required.'}), 400

    user_id, error_message = mongo_service.create_user(username, email, password, role_to_assign)
    
    if user_id:
        return jsonify({'message': 'Registration successful! You can now log in.'}), 201
    else:
        return jsonify({'message': error_message or 'Registration failed. An unknown error occurred.'}), 400

@app.route('/login', methods=['POST'])
def login():
    """API endpoint for user login from React frontend."""
    if current_user.is_authenticated:
        return jsonify({'message': 'You are already logged in.'}), 200 # Or 400/403

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    user_data = mongo_service.verify_password(username, password)
    if user_data:
        user = User(user_data)
        login_user(user)
        return jsonify({'message': f'Welcome, {user.username}!', 'redirect': url_for('index')}), 200
    else:
        return jsonify({'message': 'Invalid username or password.'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth')) # Redirect to the /auth route after logout

@app.route('/extract-id-details', methods=['POST'])
@login_required
def extract_id_details():
    if 'id_image' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['id_image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not azure_di_service:
        return jsonify({'error': 'Azure Document Intelligence service not configured.'}), 500

    extracted_data = {}
    confidence_scores = {}
    verification_status = "unverified"
    verification_message = "Verification not performed."
    verified_record_details = {}
    log_status = "error"
    log_error_message = None
    manual_review_recommended = False # Initializing the flag
    client_alert_message = None # Initializing client alert message

    try:
        image_bytes = file.read()

        if azure_di_service.custom_model_id and azure_di_service.custom_model_id != "YOUR_CUSTOM_MODEL_ID_PLACEHOLDER":
            result_data = azure_di_service.analyze_document_with_custom_model(image_bytes)
        else:
            result_data = azure_di_service.analyze_id_document(image_bytes)

        if result_data and result_data.get('data'):
            extracted_data = result_data['data']
            confidence_scores = result_data['confidence']

            extracted_id_number = extracted_data.get('ID Number')
            extracted_serial_number = extracted_data.get('Serial Number')

            # Debugging prints for extracted and normalized values
            print(f"DEBUG: Extracted ID Number (raw from DI): '{extracted_id_number}'")
            print(f"DEBUG: Extracted Serial Number (raw from DI): '{extracted_serial_number}'")
            
            # mongo_service.get_id_record_by_numbers will normalize these values internally
            if extracted_id_number and extracted_serial_number:
                print(f"DEBUG: Calling mongo_service.get_id_record_by_numbers with ID: '{extracted_id_number}', Serial: '{extracted_serial_number}'")
                verified_record = mongo_service.get_id_record_by_numbers(
                    extracted_id_number, extracted_serial_number
                )

                if verified_record:
                    verification_status = "successful"
                    verification_message = "Verification successful: Matching record found!"
                    # directly from the verified_record, which is now serialized
                    verified_record_details = {
                        "Date of Birth": verified_record.get("dateOfBirth", "N/A"),
                        "Gender": verified_record.get("gender", "N/A"),
                        "Nationality": verified_record.get("nationality", "N/A"),
                        "District of Birth": verified_record.get("distictOfBirth", "N/A"),
                        "Date of Issue": verified_record.get("dateOfIssue", "N/A"),
                        "Place of Issue": verified_record.get("placeOfIssue", "N/A"),
                    }
                    print(f"INFO: ID Verification successful for ID: {extracted_id_number}")
                    log_status = "successful"
                else:
                    verification_status = "failed"
                    verification_message = "Verification failed: No matching record found in database."
                    print(f"INFO: ID Verification failed for ID: {extracted_id_number}")
                    log_status = "failed"
            else:
                verification_status = "failed"
                verification_message = "Verification failed: Could not extract valid ID Number or Serial Number for comparison."
                print("INFO: ID Verification skipped due to missing extracted ID/Serial numbers.")
                log_status = "failed"
                log_error_message = "Missing ID Number or Serial Number for verification."
        else:
            verification_message = "No details extracted for verification."
            log_status = "failed"
            log_error_message = "No details extracted from the document."
            print("INFO: No details extracted from document.")

        # Checking overall confidence for manual review recommendation (using the value from confidence_scores)
        overall_confidence_str = confidence_scores.get('Overall Confidence', '0%')
        try:
            overall_confidence_value = float(overall_confidence_str.replace('%', ''))
            if overall_confidence_value < 75:
                manual_review_recommended = True
        except ValueError:
            print(f"WARNING: Could not parse Overall Confidence from confidence_scores: {overall_confidence_str}")
            manual_review_recommended = True # Assume manual review if confidence is unparseable


        # client_alert_message for the frontend
        if verification_status == "failed":
            client_alert_message = verification_message
            if manual_review_recommended:
                client_alert_message += "\nManual Review Recommended: Overall confidence score is below 75%. Please verify the extracted details manually."
        elif manual_review_recommended:
            client_alert_message = "Manual Review Recommended: Overall confidence score is below 75%. Please verify the extracted details manually."
        elif verification_status == "successful":
            client_alert_message = "Verification successful: Matching record found!"


        return_data = {
            'message': 'Extraction and Verification process complete.',
            'extracted_details': extracted_data, 
            'confidence': confidence_scores, 
            'verification': {
                'status': verification_status,
                'message': verification_message,
                'record_details': verified_record_details
            },
            'client_alert_message': client_alert_message 
        }
        # Passing the new flag to the logging function
        mongo_service.log_verification_job(
            user_id=current_user.id,
            username=current_user.username,
            id_number=extracted_data.get('ID Number', 'N/A'),
            status=log_status,
            timestamp=datetime.now(),
            extracted_data=extracted_data, 
            verified_data=verified_record_details if verification_status == "successful" else None,
            error_message=log_error_message,
            manual_review_recommended=manual_review_recommended,
            confidence=confidence_scores
        )
        return jsonify(return_data), 200

    except Exception as e:
        print(f"Extraction and Verification error: {e}")
        log_error_message = f'An error occurred during extraction and verification: {str(e)}'
        client_alert_message = f"An error occurred during extraction and verification: {str(e)}" # error alert
        # getting ID number for logging even if extraction failed early
        attempted_id_number = extracted_data.get('ID Number', 'N/A')
        mongo_service.log_verification_job(
            user_id=current_user.id,
            username=current_user.username,
            id_number=attempted_id_number,
            status="error",
            timestamp=datetime.now(),
            extracted_data=extracted_data, 
            verified_data=None,
            error_message=log_error_message,
            manual_review_recommended=True, 
            confidence=confidence_scores 
        )
        return jsonify({'error': log_error_message, 'client_alert_message': client_alert_message}), 500 # alert message in error response

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('Access denied. You must be an administrator to view this page.', 'error')
        return redirect(url_for('index'))

    all_users = list(mongo_service.users_collection.find({}))
    for user_doc in all_users:
        user_doc['email'] = user_doc.get('email', 'N/A')
        user_doc['role'] = 'admin' if 1 in user_doc.get('roles', []) else 'user'
        user_doc['created_at'] = user_doc.get('created_at', None)
        user_doc['last_login'] = user_doc.get('last_login', None)
        user_doc['is_active'] = user_doc.get('is_active', False)
        last_updated_by_admin_id = user_doc.get('last_updated_by_admin_id')
        if last_updated_by_admin_id:
            admin_data = mongo_service.get_user_by_id(str(last_updated_by_admin_id))
            user_doc['last_updated_by_admin_username'] = admin_data.get('username') if admin_data else 'Unknown Admin'
        else:
            user_doc['last_updated_by_admin_username'] = 'N/A'

    all_id_records = []
    if mongo_service.id_records_collection is not None:
        all_id_records = list(mongo_service.id_records_collection.find({}))
        # ensuringh ID records are serialized for the template if they contain ObjectIds/datetimes
        all_id_records = [mongo_service._serialize_mongo_doc(record) for record in all_id_records]
    else:
        print("WARNING: ID Records collection not initialized. Cannot fetch records.")

    all_verification_logs = []
    if mongo_service.verification_logs_collection is not None:
        all_verification_logs_raw = list(mongo_service.verification_logs_collection.find({}).sort("timestamp", -1))
        '''
        serializing nested data within each log entry (extracted_data, verified_data)
        but keeping the top-level 'timestamp' as datetime for strftime in template.
        '''
        for log in all_verification_logs_raw:
            if 'extracted_data' in log and log['extracted_data'] is not None:
                log['extracted_data'] = mongo_service._serialize_mongo_doc(log['extracted_data'])
            if 'verified_data' in log and log['verified_data'] is not None:
                log['verified_data'] = mongo_service._serialize_mongo_doc(log['verified_data'])
            if 'confidence' in log and log['confidence'] is not None:
                log['confidence'] = mongo_service._serialize_mongo_doc(log['confidence'])
            # Ensuring _id is stringified for all logs
            if '_id' in log:
                log['_id'] = str(log['_id'])

        all_verification_logs = all_verification_logs_raw
    else:
        print("WARNING: Verification Logs collection not initialized. Cannot fetch logs.")

    return render_template('admin_dashboard.html', users=all_users, id_records=all_id_records, verification_logs=all_verification_logs)

# --- Admin CRUD Routes (for Users) ---
@app.route('/admin/users', methods=['POST'])
@login_required
def admin_users_add_or_update():
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied.'}), 403

    user_id = request.json.get('id')
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    role = request.json.get('role')
    is_active = request.json.get('is_active', True)

    if user_id:
        success, message = mongo_service.update_user(user_id, username, email, password, role, is_active, admin_user_id=current_user.id)
        if success:
            return jsonify({'success': True, 'message': message or 'User updated successfully.'})
        else:
            # If update fails (e.g., due to password validation), return the specific message
            return jsonify({'success': False, 'message': message or 'Failed to update user.'}), 400
    else:
        success_id, message = mongo_service.create_user(username, email, password, role, admin_user_id=current_user.id)
        if success_id: # success_id will be None if creation failed due to validation
            return jsonify({'success': True, 'message': message or 'User created successfully.', 'user_id': success_id})
        else:
            # If creation fails (e.g., due to password validation), return the specific message
            return jsonify({'success': False, 'message': message or 'Failed to create user.'}), 400

@app.route('/admin/users/<user_id>', methods=['DELETE'])
@login_required
def admin_users_delete(user_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Access denied.'}), 403

    success, message = mongo_service.delete_user(user_id, admin_user_id=current_user.id)
    if success:
        return jsonify({'success': True, 'message': message or 'User deleted successfully.'})
    else:
        return jsonify({'success': False, 'message': message or 'Failed to delete user or user not found.'}), 404

# --- Export Routes ---
@app.route('/admin/export/users', methods=['GET'])
@login_required
def export_users():
    if not current_user.is_admin():
        flash('Access denied. You must be an administrator.', 'error')
        return redirect(url_for('admin_dashboard'))

    si = StringIO()
    cw = csv.writer(si)

    headers = ["User ID", "Username", "Email", "Role", "Date Created", "Last Login", "Active", "Last Updated By Admin (Username)", "Last Updated At"]
    cw.writerow(headers)

    users = mongo_service.users_collection.find({})
    for user in users:
        last_updated_by_admin_username = 'N/A'
        last_updated_by_admin_id = user.get('last_updated_by_admin_id')
        if last_updated_by_admin_id:
            admin_data = mongo_service.get_user_by_id(str(last_updated_by_admin_id))
            last_updated_by_admin_username = admin_data.get('username') if admin_data else f"ID: {last_updated_by_admin_id}"


        row = [
            str(user.get('_id')),
            user.get('username', 'N/A'),
            user.get('email', 'N/A'),
            'admin' if 1 in user.get('roles', []) else 'user',
            user.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if user.get('created_at') else 'N/A',
            user.get('last_login').strftime('%Y-%m-%d %H:%M:%S') if user.get('last_login') else 'N/A',
            'Yes' if user.get('is_active', False) else 'No',
            last_updated_by_admin_username,
            user.get('last_updated_at').strftime('%Y-%m-%d %H:%M:%S') if user.get('last_updated_at') else 'N/A'
        ]
        cw.writerow(row)

    output = si.getvalue()
    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=registered_users.csv"
    return response

@app.route('/admin/export/verification_logs', methods=['GET'])
@login_required
def export_verification_logs():
    if not current_user.is_admin():
        flash('Access denied. You must be an administrator.', 'error')
        return redirect(url_for('admin_dashboard'))

    si = StringIO()
    cw = csv.writer(si)

    headers = ["Log ID", "User ID", "Username", "Timestamp", "ID Number Attempted", "Status", "Manual Review Recommended", "Overall Confidence"] # Added Overall Confidence
    cw.writerow(headers)

    logs = mongo_service.verification_logs_collection.find({}).sort("timestamp", -1)
    '''
    Ensuring logs are serialized for CSV export as well
    _serialize_mongo_doc handles datetime to ISO string conversion.
    '''
    serialized_logs_for_csv = [mongo_service._serialize_mongo_doc(log) for log in logs]

    for log in serialized_logs_for_csv: # Iterating over serialized logs
        row = [
            str(log.get('_id')),
            str(log.get('user_id')),
            log.get('username', 'N/A'),
            log.get('timestamp', 'N/A'), #ISO formatted string due to _serialize_mongo_doc
            log.get('id_number_attempted', 'N/A'),
            log.get('status', 'N/A').capitalize(),
            'Yes' if log.get('manual_review_recommended', False) else 'No',
            log.get('confidence', {}).get('Overall Confidence', 'N/A') 
        ]
        cw.writerow(row)

    output = si.getvalue()
    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=verification_logs.csv"
    return response

# --- Ngrok and Flask Runner for Colab ---
# This block is for local development/Colab. Render will handle its own server.
def run_flask_app():
    print(f"Starting Flask application on port {FLASK_PORT}...")
    # Use 0.0.0.0 to make it accessible outside localhost (important for Colab/Docker)
    app.run(host='0.0.0.0', port=FLASK_PORT, debug=False, use_reloader=False, threaded=True)

if __name__ == '__main__':
    # Initial setup for admin user only if MongoDB is connected
    if mongo_service.client is None:
        print("CRITICAL ERROR: MongoDB connection failed at startup. Exiting.")
    else:
        admin_user_data = mongo_service.get_user_by_username('admin')
        if admin_user_data is None or (admin_user_data and 1 not in admin_user_data.get('roles', [])):
            print("\n--- Initial Setup: Admin User Not Found or Not Correctly Confirmed ---")
            print("No 'admin' user with correct roles found. Creating a default admin user.")
            print("You will be prompted for a password for the 'admin' user.")
            admin_password = input("Enter a password for the default 'admin' user: ")
            admin_email = "admin@example.com"
            if admin_password:
                admin_id, error_msg = mongo_service.create_user('admin', admin_email, admin_password, 'admin')
                if admin_id:
                    print("Default 'admin' user created successfully. Please remember this password.")
                else:
                    print(f"Failed to create default 'admin' user: {error_msg}")
            else:
                print("Admin password not provided. Default 'admin' user not created.")
            print("-------------------------------------------\n")

        # Start Flask app in a thread for Colab/local use
        flask_thread = Thread(target=run_flask_app)
        flask_thread.daemon = True # Daemonize thread so it exits when main program exits
        flask_thread.start()

        time.sleep(5) # Give Flask a moment to start

        # Ngrok tunnel setup (ONLY for Colab/local testing, NOT for Render)
        print(f"\nSetting up Ngrok tunnel for port {FLASK_PORT}...")
        try:
            # Ensure Ngrok is killed before starting a new tunnel
            # This helps prevent issues if a previous tunnel is still active
            # ngrok.kill() # Commented out for Render deployment

            # if NGROK_AUTH_TOKEN and NGROK_AUTH_TOKEN != "YOUR_NGROK_AUTH_TOKEN_PLACEHOLDER":
            #     conf.get_default().auth_token = NGROK_AUTH_TOKEN
            #     print("INFO: Ngrok authentication token applied.")
            # else:
            #     print("WARNING: NGROK_AUTH_TOKEN is missing or a placeholder. Ngrok may not connect.")
            #     print("Please ensure your .env has a valid NGROK_AUTH_TOKEN from [https://dashboard.ngrok.com/get-started/your-authtoken](https://dashboard.ngrok.com/get-started/your-authtoken)")

            # public_url = ngrok.connect(FLASK_PORT) # Commented out for Render deployment
            # print(f"Ngrok tunnel established: {public_url}")
            # print("\nYour Flask app is now publicly accessible at this URL.")
            # print("You can open this URL in your browser to interact with the application.")
            # print("\nNote: The Ngrok tunnel will remain active as long as this cell is running.")
            # print("If you restart the cell, a new public URL will be generated.")
            # print("Free Ngrok sessions typically expire after a few hours.")

            # Keep the main thread alive to allow Flask and Ngrok (if uncommented) to run
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("Server stopped by user.")
            finally:
                # ngrok.kill() # Commented out for Render deployment
                pass # No Ngrok to kill for Render

        except Exception as e:
            print(f"Error starting Ngrok tunnel: {e}")
            print("Please ensure your NGROK_AUTH_TOKEN is correct and try again.")
            print("Also, check if port 5000 is free (though unlikely in Colab).")
            if flask_thread.is_alive():
                print("Flask app might still be running in background. You may need to restart runtime.")
