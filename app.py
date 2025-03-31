import eventlet
eventlet.monkey_patch()
import uuid
from datetime import datetime, timezone, timedelta  # Corrected import
import functools
import logging
import os
import jwt
import requests
from flask import Flask, redirect, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import boto3
from boto3.dynamodb.conditions import Key, Attr
import base64
from decimal import Decimal
from collections import defaultdict
from flask_socketio import SocketIO, join_room, leave_room, emit

from urllib.parse import urlencode
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

# OCR-related imports
import re
from PIL import Image
import pytesseract

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# CORS configuration
CORS(app,
     supports_credentials=True,
     resources={r"/*": {
         "origins": "*",
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Authorization", "Content-Type"],
         "expose_headers": ["Authorization"]
     }})

app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# Initialize SocketIO for real-time chat with Eventlet
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Google OAuth settings
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))

# DynamoDB setup
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)

# Tables (using environment variables with fallback defaults)
users_table = dynamodb.Table(os.getenv('DYNAMODB_USERS_TABLE', 'Users'))
groups_table = dynamodb.Table(os.getenv('DYNAMODB_GROUPS_TABLE', 'Groups'))
expenses_table = dynamodb.Table(os.getenv('DYNAMODB_EXPENSES_TABLE', 'Expenses'))
transactions_table = dynamodb.Table(os.getenv('DYNAMODB_TRANSACTIONS_TABLE', 'Transactions'))
chats_table = dynamodb.Table(os.getenv('DYNAMODB_CHATS_TABLE', 'Chats'))

# OCR upload folder configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function: recursively convert floats to Decimals (if needed)
def convert_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, list):
        return [convert_to_decimal(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_to_decimal(value) for key, value in obj.items()}
    else:
        return obj

# Token validation decorator
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return jsonify({}), 200

        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            response = users_table.get_item(Key={"UserID": data['user_id']})
            if "Item" not in response:
                return jsonify({'message': 'User not found'}), 401
            current_user = response["Item"]
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Token error: {e}")
            return jsonify({'message': 'Error processing token'}), 500
        return f(current_user, *args, **kwargs)
    return decorated

# ------------------------
# OCR Functions and Routes
# ------------------------

# Function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to extract receipt details using OCR
def extract_details_from_receipt(image_path):
    """Extracts shop name, date, total amount, and item details from a Dmart receipt"""

    # Load and OCR the image
    image = Image.open(image_path)
    ocr_text = pytesseract.image_to_string(image)

    # Extract shop name
    shop_name = "Dmart" if "DMART" in ocr_text.upper() else "Unknown"

    # Extract date (formats: dd/mm/yyyy or dd-mm-yyyy)
    date_pattern = r'(\d{2}[/\-]\d{2}[/\-]\d{4})'
    date_match = re.search(date_pattern, ocr_text)
    date = date_match.group(0) if date_match else "Date not found"

    # Extract total amount
    total_pattern = r'Total\s*[:Rs.]\s([\d.,]+)'
    total_match = re.search(total_pattern, ocr_text)
    total_amount = f"Rs. {total_match.group(1)}" if total_match else "Total not found"

    # Extract itemized details
    items = []
    item_pattern = re.compile(
        r'(\d{6,})\s+([A-Z0-9\s\-?\/,.&]+)\s+[-~]\s*(\d+)\s+([\d.]+)\s+([\d.]+)'
    )

    for match in item_pattern.finditer(ocr_text):
        item_code = match.group(1)
        item_name = match.group(2).strip()
        qty = int(match.group(3))
        rate = float(match.group(4))
        price = float(match.group(5))

        items.append({
            "code": item_code,
            "item": item_name,
            "quantity": qty,
            "rate": rate,
            "price": price
        })

    # Combine results
    expense_details = {
        "Shop Name": shop_name,
        "Date": date,
        "Total Amount": total_amount,
        "Items": items
    }

    return expense_details

@app.route('/api/ocr/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    """Handles image upload and performs OCR"""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        # Use os.path.basename to safely handle filename
        filename = os.path.basename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
       
        # Save the uploaded image
        file.save(filepath)

        # Perform OCR extraction
        results = extract_details_from_receipt(filepath)

        # Clean up uploaded file
        os.remove(filepath)

        return jsonify(results)

    return jsonify({"error": "Invalid file format"}), 400

@app.route('/api/ocr/scan', methods=['GET'])
@token_required
def ocr_info(current_user):
    return jsonify({"message": "Receipt OCR API is active", "supported_formats": list(ALLOWED_EXTENSIONS)})


# ------------------------
# Google OAuth & User Routes
# ------------------------

@app.route("/api/verify-email", methods=["POST"])
def verify_email():
    data = request.json
    token = data.get("token")
    if not token:
        return jsonify({"success": False, "error": "No token provided"}), 400
    try:
        email = base64.b64decode(token).decode()
    except Exception as e:
        return jsonify({"success": False, "error": "Invalid token"}), 400
    try:
        response = users_table.query(
            IndexName="EmailIndex",
            KeyConditionExpression=Key("Email").eq(email)
        )
        if not response.get("Items"):
            return jsonify({"success": False, "error": "User not found"}), 404
        user = response["Items"][0]
        users_table.update_item(
            Key={"UserID": user["UserID"]},
            UpdateExpression="SET verified = :val",
            ExpressionAttributeValues={":val": True},
            ReturnValues="UPDATED_NEW"
        )
        return jsonify({"success": True, "message": "Email verified successfully!"})
    except Exception as e:
        logger.error(f"verify_email error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

def get_google_provider_cfg():
    try:
        cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        logger.debug("Fetched Google provider configuration successfully")
        return cfg
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Google OpenID config: {e}")
        return None

@app.route("/api/login")
def login():
    try:
        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            logger.error("Failed to fetch Google configuration")
            return jsonify({'error': 'Unable to fetch Google configuration'}), 500
        
        authorization_endpoint = google_cfg["authorization_endpoint"]
        frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:5173/auth/callback")
        logger.debug(f"Using FRONTEND_CALLBACK_URL: {frontend_callback}")
        
        request_uri = requests.Request(
            'GET',
            authorization_endpoint,
            params={
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": frontend_callback,
                "scope": "openid email profile",
                "response_type": "code",
                "access_type": "offline",
                "prompt": "consent"
            }
        ).prepare().url
        
        logger.info(f"Redirecting to Google OAuth URL: {request_uri}")
        return redirect(request_uri)
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication process failed'}), 500

# @app.route("/api/callback")
# def callback():
#     try:
#         code = request.args.get("code")
#         if not code:
#             logger.error("Authorization code missing in callback")
#             return jsonify({'error': 'Authorization code missing'}), 400
        
#         logger.info(f"Received authorization code: {code}")
#         google_cfg = get_google_provider_cfg()
#         if not google_cfg:
#             return jsonify({'error': 'Unable to fetch Google configuration'}), 500
        
#         token_endpoint = google_cfg["token_endpoint"]
#         frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:5173/auth/callback")
#         logger.debug(f"Using redirect_uri for token exchange: {frontend_callback}")
        
#         token_response = requests.post(
#             token_endpoint,
#             data={
#                 "code": code,
#                 "client_id": GOOGLE_CLIENT_ID,
#                 "client_secret": GOOGLE_CLIENT_SECRET,
#                 "redirect_uri": frontend_callback,
#                 "grant_type": "authorization_code"
#             }
#         )
#         if not token_response.ok:
#             logger.error(f"Token exchange failed: {token_response.text}")
#             return jsonify({'error': 'Failed to retrieve token from Google'}), 400
        
#         token_json = token_response.json()
#         access_token = token_json.get("access_token")
#         logger.debug(f"Access token received: {access_token}")
        
#         userinfo_endpoint = google_cfg["userinfo_endpoint"]
#         userinfo_response = requests.get(
#             userinfo_endpoint,
#             headers={"Authorization": f"Bearer {access_token}"}
#         )
#         if not userinfo_response.ok:
#             logger.error(f"User info fetch failed: {userinfo_response.text}")
#             return jsonify({'error': 'Failed to retrieve user information'}), 400
        
#         userinfo = userinfo_response.json()
#         logger.debug(f"User info: {userinfo}")
        
#         if not userinfo.get("email_verified", False):
#             logger.error("Email not verified by Google")
#             return jsonify({'error': 'Email not verified by Google'}), 400
        
#         email = userinfo["email"]
#         logger.debug(f"User email: {email}")
        
#         query_response = users_table.query(
#             IndexName="EmailIndex",
#             KeyConditionExpression=Key("Email").eq(email)
#         )
        
#         now_iso = datetime.now(timezone.utc).isoformat()  # Fixed datetime usage
#         if query_response.get("Items"):
#             user_record = query_response["Items"][0]
#             user_id = user_record["UserID"]
#             try:
#                 users_table.update_item(
#                     Key={"UserID": user_id},
#                     UpdateExpression="SET #name = :name, picture = :picture, last_login = :last_login",
#                     ExpressionAttributeNames={"#name": "name"},
#                     ExpressionAttributeValues={
#                         ":name": userinfo.get("name", ""),
#                         ":picture": userinfo.get("picture", ""),
#                         ":last_login": now_iso
#                     }
#                 )
#                 user_record.update({
#                     "name": userinfo.get("name", ""),
#                     "picture": userinfo.get("picture", ""),
#                     "last_login": now_iso
#                 })
#                 logger.info(f"Existing user updated: {email}")
#             except Exception as e:
#                 logger.error(f"DynamoDB update failed: {e}")
#                 return jsonify({'error': 'Database operation failed'}), 500
#         else:
#             user_id = str(uuid.uuid4())
#             user_record = {
#                 "UserID": user_id,
#                 "Email": email,
#                 "name": userinfo.get("name", ""),
#                 "picture": userinfo.get("picture", ""),
#                 "created_at": now_iso,
#                 "last_login": now_iso
#             }
#             try:
#                 users_table.put_item(Item=user_record)
#                 logger.info(f"New user created: {email} with UserID: {user_id}")
#             except Exception as e:
#                 logger.error(f"DynamoDB put_item failed: {e}")
#                 return jsonify({'error': 'Database operation failed'}), 500
        
#         try:
#             exp_time = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)  # Fixed datetime and timedelta
#             payload = {
#                 'user_id': user_id,
#                 'exp': exp_time
#             }
#             token = jwt.encode(payload, app.secret_key, algorithm='HS256')
#             logger.debug("JWT token generated successfully")
#             return jsonify({
#                 'token': token,
#                 'user': user_record,
#                 'expires': exp_time.isoformat()
#             })
#         except Exception as e:
#             logger.error(f"Token generation failed: {e}")
#             return jsonify({'error': 'Authentication failed'}), 500
#     except Exception as e:
#         logger.error(f"Callback error: {e}")
#         return jsonify({'error': 'Authentication process failed'}), 500


# Updated callback route (replace existing)
@app.route("/api/callback", methods=["GET", "POST"])
def callback():
    try:
        # Handle both GET and POST requests
        code = request.args.get("code") or (request.json and request.json.get("code"))
        if not code:
            logger.error("Authorization code missing in callback")
            return jsonify({'error': 'Authorization code missing'}), 400

        logger.info(f"Processing OAuth callback with code: {code[:15]}...")
        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            return jsonify({'error': 'Unable to fetch Google configuration'}), 500

        # Prepare token request
        token_endpoint = google_cfg["token_endpoint"]
        frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:5173/auth/callback")
        
        # Exchange authorization code for tokens
        token_response = requests.post(
            token_endpoint,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": frontend_callback,
                "grant_type": "authorization_code"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if not token_response.ok:
            logger.error(f"Token exchange failed: {token_response.text}")
            return jsonify({
                'error': 'Failed to retrieve tokens',
                'details': token_response.json()
            }), 400

        token_data = token_response.json()
        access_token = token_data.get("access_token")
        id_token = token_data.get("id_token")

        # Get user info from Google
        userinfo_endpoint = google_cfg["userinfo_endpoint"]
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if not userinfo_response.ok:
            logger.error(f"User info fetch failed: {userinfo_response.text}")
            return jsonify({'error': 'Failed to retrieve user information'}), 400

        userinfo = userinfo_response.json()
        logger.debug(f"User info received: {userinfo}")

        # Validate email verification
        if not userinfo.get("email_verified", False):
            logger.error("Email not verified by Google")
            return jsonify({'error': 'Email not verified by Google'}), 400

        email = userinfo["email"]
        logger.info(f"Processing login for user: {email}")

        # Check for existing user
        response = users_table.query(
            IndexName="EmailIndex",
            KeyConditionExpression=Key("Email").eq(email)
        )
        users = response.get("Items", [])
        now_iso = datetime.now(timezone.utc).isoformat()

        if users:
            # Update existing user
            user = users[0]
            update_expression = [
                "SET #name = :name",
                "picture = :picture",
                "last_login = :last_login"
            ]
            expression_values = {
                ":name": userinfo.get("name", user.get("name", "")),
                ":picture": userinfo.get("picture", user.get("picture", "")),
                ":last_login": now_iso
            }
            
            users_table.update_item(
                Key={"UserID": user["UserID"]},
                UpdateExpression=", ".join(update_expression),  # Commas added here
                ExpressionAttributeNames={"#name": "name"},
                ExpressionAttributeValues=expression_values
            )
            user_id = user["UserID"]
            logger.info(f"Updated existing user: {user_id}")
        else:
            # Create new user
            user_id = str(uuid.uuid4())
            new_user = {
                "UserID": user_id,
                "Email": email,
                "name": userinfo.get("name", ""),
                "picture": userinfo.get("picture", ""),
                "created_at": now_iso,
                "last_login": now_iso,
                "verified": True
            }
            
            users_table.put_item(Item=new_user)
            logger.info(f"Created new user: {user_id}")
            user = new_user

        # Generate JWT token
        exp_time = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
        token_payload = {
            'user_id': user_id,
            'exp': exp_time,
            'email': email
        }
        
        try:
            jwt_token = jwt.encode(token_payload, app.secret_key, algorithm='HS256')
        except Exception as e:
            logger.error(f"JWT encoding failed: {str(e)}")
            return jsonify({'error': 'Token generation failed'}), 500

        # Prepare response
        response_data = {
            'token': jwt_token,
            'user': {
                'UserID': user_id,
                'Email': email,
                'name': user.get('name'),
                'picture': user.get('picture')
            },
            'expires': exp_time.isoformat()
        }

        # For GET requests, redirect with token in URL hash
        if request.method == "GET":
            frontend_url = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:5173/auth/callback")
            redirect_url = f"{frontend_url}#{urlencode(response_data)}"
            return redirect(redirect_url)
        
        # For POST requests, return JSON
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Callback processing failed: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Authentication process failed',
            'details': str(e)
        }), 500
    

@app.route("/api/user", methods=["GET"])
@token_required
def get_user(current_user):
    logger.debug("Returning current user profile")
    return jsonify(current_user)

@app.route("/api/logout", methods=["POST"])
@token_required
def logout(current_user):
    logger.info(f"User logged out: {current_user['Email']}")
    return jsonify({'message': 'Successfully logged out'})

@app.route("/api/dashboard")
@token_required
def dashboard(current_user):
    logger.debug("Dashboard accessed by user")
    return jsonify({
        'message': 'You have access to the dashboard',
        'user': current_user
    })

# ------------------------
# Groups Endpoints
# ------------------------

@app.route("/api/groups", methods=["POST"])
@token_required
def create_group(current_user):
    try:
        data = request.get_json()
        if not data or "name" not in data:
            logger.error("Group name is required")
            return jsonify({'error': 'Group name is required'}), 400
        
        group_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()  # Fixed
        
        group_data = {
            "GroupID": group_id,
            "name": data.get("name"),
            "createdBy": current_user.get("Email"),
            "members": data.get("members", []),
            "createdAt": now_iso
        }
        if not any(member.get("email") == current_user.get("Email") for member in group_data["members"]):
            group_data["members"].append({"email": current_user.get("Email")})
        
        groups_table.put_item(Item=group_data)
        logger.info(f"Group created successfully: {group_id}")
        return jsonify({'message': 'Group created successfully', 'group': group_data}), 201
    except Exception as e:
        logger.error(f"Error creating group: {e}")
        return jsonify({'error': 'Failed to create group'}), 500

@app.route("/api/groups/<group_id>", methods=["GET"])
@token_required
def get_group(current_user, group_id):
    try:
        logger.debug(f"Fetching group with GroupID: {group_id}")
        response = groups_table.get_item(Key={"GroupID": group_id})
        if "Item" not in response:
            logger.error("Group not found")
            return jsonify({'error': 'Group not found'}), 404
        
        group = response["Item"]
        user_email = current_user.get("Email")
        if group.get("createdBy") != user_email and not any(member.get("email") == user_email for member in group.get("members", [])):
            logger.error("User not authorized to view this group")
            return jsonify({'error': 'Not authorized to view this group'}), 403
        
        logger.debug("Group found, returning group data")
        return jsonify(group)
    except Exception as e:
        logger.error(f"Error fetching group: {e}")
        return jsonify({'error': 'Failed to fetch group'}), 500

@app.route("/api/groups", methods=["GET"])
@token_required
def get_all_groups(current_user):
    try:
        logger.debug("Scanning all groups from DynamoDB")
        response = groups_table.scan()
        all_groups = response.get('Items', [])
        
        user_email = current_user.get('Email')
        filtered_groups = []
        for group in all_groups:
            if group.get('createdBy') == user_email or any(member.get('email') == user_email for member in group.get('members', [])):
                filtered_groups.append(group)
        
        if not filtered_groups:
            logger.error("No groups found for this user")
            return jsonify({'error': 'No groups found'}), 404
        
        logger.info("Groups retrieved successfully for this user")
        return jsonify(filtered_groups), 200
    except Exception as e:
        logger.error(f"Error fetching groups: {e}")
        return jsonify({'error': 'Failed to fetch groups'}), 500

# ------------------------
# Debt Settlement Endpoint
# ------------------------
@app.route("/api/groups/<group_id>/settle", methods=["POST"])
@token_required
def settle_group_debts(current_user, group_id):
    try:
        # Retrieve group details
        group_response = groups_table.get_item(Key={"GroupID": group_id})
        if "Item" not in group_response:
            return jsonify({"error": "Group not found"}), 404

        group = group_response["Item"]
        user_email = current_user["Email"]
        # Check authorization using emails
        if group["createdBy"] != user_email and not any(m.get("email") == user_email for m in group.get("members", [])):
            return jsonify({"error": "Unauthorized"}), 403

        # Fetch all expenses for the group
        expenses = []
        last_key = None
        while True:
            scan_args = {"FilterExpression": Attr("GroupID").eq(group_id)}
            if last_key:
                scan_args["ExclusiveStartKey"] = last_key
            response = expenses_table.scan(**scan_args)
            expenses.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break

        # Initialize balances for each group member
        balances = defaultdict(Decimal)
        member_emails = {m["email"] for m in group.get("members", []) if m.get("email")}
        for email in member_emails:
            balances[email] = Decimal("0")

        # Process each expense
        for expense in expenses:
            paid_by = expense.get("paidBy")
            if not paid_by or paid_by not in balances:
                continue

            for split in expense.get("splits", []):
                if "M" in split:
                    split_data = split["M"]
                    if "memberId" not in split_data or "amount" not in split_data:
                        continue
                    member_id = split_data["memberId"].get("S")
                    amount = Decimal(split_data["amount"].get("N", "0"))
                else:
                    split_data = split
                    if "memberId" not in split_data:
                        continue
                    member_id = split_data["memberId"]
                    amount = Decimal(str(split_data["amount"]))
                
                if not member_id:
                    continue

                if member_id not in balances:
                    continue

                if member_id != paid_by:
                    balances[member_id] -= amount
                    balances[paid_by] += amount

        # Minimal Cash Flow Algorithm
        def min_cash_flow(bal_list):
            if all(abs(b) < Decimal("0.01") for _, b in bal_list):
                return []
            max_creditor = max(bal_list, key=lambda x: x[1])
            max_debtor = min(bal_list, key=lambda x: x[1])
            settle_amt = min(max_creditor[1], -max_debtor[1])
            txn = {
                "TransactionID": str(uuid.uuid4()),
                "GroupID": group_id,
                "From": max_debtor[0],
                "To": max_creditor[0],
                "Amount": settle_amt,
                "Date": datetime.now(timezone.utc).isoformat(),  # Fixed
                "Status": "pending",
                "CreatedBy": current_user["UserID"]
            }
            new_bal_list = []
            for email, bal in bal_list:
                if email == max_creditor[0]:
                    new_bal_list.append((email, bal - settle_amt))
                elif email == max_debtor[0]:
                    new_bal_list.append((email, bal + settle_amt))
                else:
                    new_bal_list.append((email, bal))
            return [txn] + min_cash_flow(new_bal_list)

        balance_list = list(balances.items())
        transactions = min_cash_flow(balance_list)

        # Update transactions
        existing_txs = transactions_table.query(
            IndexName="GroupIndex",
            KeyConditionExpression=Key("GroupID").eq(group_id)
        )["Items"]
        with transactions_table.batch_writer() as batch:
            for tx in existing_txs:
                batch.delete_item(Key={"TransactionID": tx["TransactionID"]})
            for tx in transactions:
                batch.put_item(Item=tx)

        return jsonify({
            "message": "Debts settled successfully",
            "transactions": [{
                "TransactionID": tx["TransactionID"],
                "From": tx["From"],
                "To": tx["To"],
                "Amount": str(tx["Amount"]),
                "Date": tx["Date"],
                "Status": tx["Status"]
            } for tx in transactions]
        }), 200

    except Exception as e:
        logger.error(f"Settlement error: {str(e)}")
        return jsonify({"error": "Failed to settle debts"}), 500

# ------------------------
# Expenses Endpoints
# ------------------------

@app.route("/api/expenses", methods=["POST", "OPTIONS"])
@token_required
def create_expense(current_user):
    if request.method == "OPTIONS":
        return jsonify({}), 200
        
    try:
        data = request.get_json()
        group_id = data.get("groupId") or data.get("GroupID")
        if not data or not group_id:
            return jsonify({'error': 'Invalid request'}), 400

        group = groups_table.get_item(Key={"GroupID": group_id}).get("Item")
        if not group:
            return jsonify({'error': 'Group not found'}), 404
            
        user_email = current_user["Email"]
        if group["createdBy"] != user_email and not any(m["email"] == user_email for m in group["members"]):
            return jsonify({'error': 'Unauthorized'}), 403

        now = datetime.now(timezone.utc).isoformat()  # Fixed
        data.update({
            "createdBy": current_user["UserID"],
            "paidBy": user_email,
            "createdAt": now,
            "updatedAt": now,
            "GroupID": group_id
        })

        if "amount" in data:
            data["amount"] = Decimal(str(data["amount"]))
        if "splits" in data:
            for split in data["splits"]:
                split["amount"] = Decimal(str(split["amount"]))

        expenses_table.put_item(Item=data)
        return jsonify({'message': 'Expense created', 'expense': data}), 201

    except Exception as e:
        logger.error(f"Expense error: {str(e)}")
        return jsonify({'error': 'Failed to create expense'}), 500

@app.route("/api/expenses/group/<group_id>", methods=["GET", "OPTIONS"])
@token_required
def get_expenses_by_group(current_user, group_id):
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        group_response = groups_table.get_item(Key={"GroupID": group_id})
        if "Item" not in group_response:
            logger.error("Group not found")
            return jsonify({'error': 'Group not found'}), 404
        
        group = group_response["Item"]
        user_email = current_user.get("Email")
        if group.get("createdBy") != user_email and not any(member.get("email") == user_email for member in group.get("members", [])):
            logger.error("User not authorized to view expenses for this group")
            return jsonify({'error': 'User not authorized for this group'}), 403

        last_evaluated_key = None
        expenses = []
        while True:
            scan_kwargs = {
                "FilterExpression": Attr("GroupID").eq(group_id)
            }
            if last_evaluated_key:
                scan_kwargs["ExclusiveStartKey"] = last_evaluated_key
            response = expenses_table.scan(**scan_kwargs)
            expenses.extend(response.get("Items", []))
            last_evaluated_key = response.get("LastEvaluatedKey")
            if not last_evaluated_key:
                break

        logger.info(f"Expenses fetched for group {group_id}: {expenses}")
        return jsonify(expenses), 200
    except Exception as e:
        logger.error(f"Error fetching expenses for group {group_id}: {str(e)}")
        return jsonify({"error": "Failed to fetch expenses for group"}), 500

# ------------------------
# Transactions Endpoints
# ------------------------

@app.route("/api/transactions", methods=["POST"])
@token_required
def create_transaction(current_user):
    try:
        data = request.get_json()
        if not data or "TransactionID" not in data or "GroupID" not in data:
            return jsonify({'error': 'TransactionID and GroupID are required'}), 400
        
        data["CreatedBy"] = current_user["UserID"]
        data["Date"] = datetime.now(timezone.utc).isoformat()  # Fixed
        
        if "Amount" in data:
            data["Amount"] = Decimal(str(data["Amount"]))
        
        transactions_table.put_item(Item=data)
        return jsonify({'message': 'Transaction created', 'transaction': data}), 201
    except Exception as e:
        logger.error(f"Transaction error: {str(e)}")
        return jsonify({'error': 'Failed to create transaction'}), 500

@app.route("/api/transactions/<transaction_id>", methods=["GET"])
@token_required
def get_transaction(current_user, transaction_id):
    try:
        logger.debug(f"Fetching transaction with TransactionID: {transaction_id}")
        response = transactions_table.get_item(Key={"TransactionID": transaction_id})
        if "Item" not in response:
            logger.error("Transaction not found")
            return jsonify({'error': 'Transaction not found'}), 404
        logger.info("Transaction fetched successfully")
        return jsonify(response["Item"])
    except Exception as e:
        logger.error(f"Error fetching transaction: {e}")
        return jsonify({'error': 'Failed to fetch transaction'}), 500

@app.route("/api/transactions/group/<group_id>", methods=["GET"])
@token_required
def get_transactions_by_group(current_user, group_id):
    try:
        logger.debug(f"Fetching transactions for GroupID: {group_id}")
        response = transactions_table.query(
            IndexName="GroupIndex",
            KeyConditionExpression=Key("GroupID").eq(group_id)
        )
        items = response.get("Items", [])
        logger.info("Transactions fetched successfully for group")
        return jsonify({'transactions': items})
    except Exception as e:
        logger.error(f"Error fetching transactions by group: {e}")
        return jsonify({'error': 'Failed to fetch transactions for group'}), 500

# ------------------------
# Chat Endpoints (WebSocket & API)
# ------------------------

@socketio.on('connect')
def on_connect():
    logger.info("Client connected via WebSocket")
    emit("status", {"msg": "Connected to server"})

@socketio.on('disconnect')
def on_disconnect():
    logger.info("Client disconnected from WebSocket")

@socketio.on('join')
def handle_join(data):
    group_id = data.get("groupId")
    email = data.get("email")
    
    if not (group_id and email):
        logger.error("Join event missing groupId or email.")
        return
        
    join_room(group_id)
    emit("status", {"msg": f"{email} has joined the chat."}, room=group_id)
    logger.info(f"{email} joined chat room: {group_id}")
    
    try:
        chats = []
        last_key = None
        
        while True:
            scan_kwargs = {
                "FilterExpression": Attr("GroupID").eq(group_id)
            }
            if last_key:
                scan_kwargs["ExclusiveStartKey"] = last_key
                
            response = chats_table.scan(**scan_kwargs)
            chats.extend(response.get("Items", []))
            
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
        
        messages = []
        for chat in chats:
            messages.append({
                "sender": chat.get("Email", "unknown"),
                "text": chat.get("Message", ""),
                "timestamp": chat.get("Timestamp", "")
            })
        
        sorted_messages = sorted(messages, key=lambda x: x.get("timestamp", ""))
        emit("chat_history", {"messages": sorted_messages})
        logger.info(f"Sent chat history ({len(sorted_messages)} messages) to {email}")
        
    except Exception as e:
        logger.error(f"Error sending chat history for group {group_id}: {str(e)}")
        emit("error", {"message": "Failed to load chat history"})

@socketio.on('leave')
def handle_leave(data):
    group_id = data.get("groupId")
    email = data.get("email")
    if group_id and email:
        leave_room(group_id)
        emit("status", {"msg": f"{email} has left the chat."}, room=group_id)
        logger.info(f"{email} left chat room: {group_id}")
    else:
        logger.error("Leave event missing groupId or email.")

@socketio.on('message')
def handle_message(data):
    group_id = data.get("groupId")
    email = data.get("sender") or data.get("email")
    message_text = data.get("text") or data.get("message")
    
    if not (group_id and email and message_text):
        logger.error("Message event missing data")
        return

    message_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')  # Fixed

    try:
        chats_table.put_item(
            Item={
                "ChatID": message_id,
                "GroupID": group_id,
                "Email": email,
                "Message": message_text,
                "Timestamp": timestamp
            }
        )
        logger.info(f"Stored message from {email} in group {group_id}")
    except Exception as e:
        logger.error(f"Failed to store chat message: {e}")
        emit("error", {"message": "Failed to save your message"}, room=request.sid)
        return

    emit("new_message", {"sender": email, "text": message_text, "timestamp": timestamp}, room=group_id)

@app.route("/api/chats", methods=["GET"])
@token_required
def get_chats(current_user):
    group_id = request.args.get("groupId")
    if not group_id:
        return jsonify({"error": "Missing groupId parameter"}), 400
        
    try:
        chats = []
        last_key = None
        
        while True:
            scan_kwargs = {
                "FilterExpression": Attr("GroupID").eq(group_id)
            }
            if last_key:
                scan_kwargs["ExclusiveStartKey"] = last_key
                
            response = chats_table.scan(**scan_kwargs)
            chats.extend(response.get("Items", []))
            
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
        
        messages = []
        for chat in chats:
            messages.append({
                "sender": chat.get("Email", "unknown"),
                "text": chat.get("Message", ""),
                "timestamp": chat.get("Timestamp", "")
            })
        
        sorted_messages = sorted(messages, key=lambda x: x.get("timestamp", ""))
        return jsonify(sorted_messages), 200
    except Exception as e:
        logger.error(f"Error fetching chats for group {group_id}: {str(e)}")
        return jsonify({"error": f"Failed to fetch chats: {str(e)}"}), 500

# ------------------------
# Error Handlers
# ------------------------

@app.errorhandler(404)
def not_found(e):
    logger.error("404 Not Found: Resource not found")
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 Internal Server Error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(405)
def method_not_allowed(e):
    logger.error(f"405 Method Not Allowed: {str(e)}")
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/')
def index():
    return jsonify({"message": "Welcome to the API!"})

@app.route('/health')
def health_check():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat()  # Fixed
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")