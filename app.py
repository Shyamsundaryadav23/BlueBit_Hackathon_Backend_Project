from gevent import monkey
monkey.patch_all()

import uuid
from datetime import datetime, timezone, timedelta
import functools
import logging
import os
import jwt
import requests
from flask import Flask, session, redirect, request, jsonify
from flask_cors import CORS
from flask_session import Session
from dotenv import load_dotenv
import boto3
from boto3.dynamodb.conditions import Key, Attr
import base64
from decimal import Decimal
from collections import defaultdict
from flask_socketio import SocketIO, join_room, leave_room, emit
import hashlib
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

# Configure session management
app.secret_key = os.getenv('SECRET_KEY', 'your-very-secure-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
Session(app)

# CORS configuration
CORS(app,
     supports_credentials=True,
     resources={r"/*": {
         "origins": "*",
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Authorization", "Content-Type"],
         "expose_headers": ["Authorization"]
     }})

# Initialize SocketIO using Gevent
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# Google OAuth settings
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))

# DynamoDB setup
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)

# Initialize DynamoDB tables using environment variables if set
tables = {
    'users': 'Users',
    'groups': 'Groups',
    'expenses': 'Expenses',
    'transactions': 'Transactions',
    'chats': 'Chats'
}
for table in tables:
    tables[table] = dynamodb.Table(os.getenv(f'DYNAMODB_{table.upper()}_TABLE', tables[table]))

# Define table variables for easier access
users_table = tables['users']
groups_table = tables['groups']
expenses_table = tables['expenses']
transactions_table = tables['transactions']
chats_table = tables['chats']

# OCR configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper functions
def convert_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, list):
        return [convert_to_decimal(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_to_decimal(value) for key, value in obj.items()}
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

# OCR Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_details_from_receipt(image_path):
    image = Image.open(image_path)
    ocr_text = pytesseract.image_to_string(image)

    shop_name = "Dmart" if "DMART" in ocr_text.upper() else "Unknown"

    date_match = re.search(r'(\d{2}[/\-]\d{2}[/\-]\d{4})', ocr_text)
    date = date_match.group(0) if date_match else "Date not found"

    total_match = re.search(r'Total\s*[:Rs.]\s([\d.,]+)', ocr_text)
    total_amount = f"Rs. {total_match.group(1)}" if total_match else "Total not found"

    items = []
    item_pattern = re.compile(r'(\d{6,})\s+([A-Z0-9\s\-?\/,.&]+)\s+[-~]\s*(\d+)\s+([\d.]+)\s+([\d.]+)')
    for match in item_pattern.finditer(ocr_text):
        items.append({
            "code": match.group(1),
            "item": match.group(2).strip(),
            "quantity": int(match.group(3)),
            "rate": float(match.group(4)),
            "price": float(match.group(5))
        })

    return {
        "Shop Name": shop_name,
        "Date": date,
        "Total Amount": total_amount,
        "Items": items
    }

# Routes
@app.route('/api/ocr/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file"}), 400

    filename = os.path.basename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        results = extract_details_from_receipt(filepath)
    finally:
        os.remove(filepath)

    return jsonify(results)

@app.route('/api/ocr/scan', methods=['GET'])
@token_required
def ocr_info(current_user):
    return jsonify({"message": "Receipt OCR API active", "formats": list(ALLOWED_EXTENSIONS)})

# OAuth Routes
def get_google_provider_cfg():
    try:
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Google config error: {e}")
        return None

@app.route("/api/login")
def login():
    try:
        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            raise ValueError("Failed to fetch Google configuration")

        state = str(uuid.uuid4())
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip('=')
        session['oauth_state'] = state
        session['code_verifier'] = code_verifier

        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')

        return redirect(requests.Request(
            'GET',
            google_cfg["authorization_endpoint"],
            params={
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": os.getenv("BACKEND_CALLBACK_URL"),
                "scope": "openid email profile",
                "response_type": "code",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "access_type": "offline",
                "prompt": "consent"
            }
        ).prepare().url)

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route("/api/callback")
def callback():
    try:
        frontend_base = os.getenv('FRONTEND_BASE_URL', 'http://localhost:5173')
        if request.args.get('state') != session.get('oauth_state'):
            logger.error("State mismatch")
            return redirect(f"{frontend_base}/login?error=invalid_state")

        code = request.args.get("code")
        code_verifier = session.pop('code_verifier', None)
        if not code or not code_verifier:
            return redirect(f"{frontend_base}/login?error=invalid_request")

        google_cfg = get_google_provider_cfg()
        token_response = requests.post(
            google_cfg["token_endpoint"],
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": os.getenv("BACKEND_CALLBACK_URL"),
                "grant_type": "authorization_code",
                "code_verifier": code_verifier
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if not token_response.ok:
            logger.error(f"Token exchange failed: {token_response.text}")
            return redirect(f"{frontend_base}/login?error=token_failed")

        access_token = token_response.json().get('access_token')
        userinfo = requests.get(
            google_cfg["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()

        if not userinfo.get('email_verified', False):
            return redirect(f"{frontend_base}/login?error=email_unverified")

        email = userinfo['email']
        now_iso = datetime.now(timezone.utc).isoformat()
        user_data = {
            "name": userinfo.get('name', ''),
            "picture": userinfo.get('picture', ''),
            "last_login": now_iso
        }

        # User management
        response = users_table.query(
            IndexName="EmailIndex",
            KeyConditionExpression=Key("Email").eq(email)
        )
        users = response.get('Items', [])

        if users:
            user_id = users[0]['UserID']
            users_table.update_item(
                Key={"UserID": user_id},
                UpdateExpression="SET #name = :name, picture = :picture, last_login = :last_login",
                ExpressionAttributeNames={"#name": "name"},
                ExpressionAttributeValues={
                    ":name": user_data["name"],
                    ":picture": user_data["picture"],
                    ":last_login": user_data["last_login"]
                }
            )
        else:
            user_id = str(uuid.uuid4())
            users_table.put_item(Item={
                "UserID": user_id,
                "Email": email,
                "created_at": now_iso,
                **user_data,
                "verified": True
            })

        jwt_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
        }, app.secret_key, algorithm='HS256')

        return redirect(f"{frontend_base}/auth/callback#token={jwt_token}")

    except Exception as e:
        frontend_base = os.getenv('FRONTEND_BASE_URL', 'http://localhost:5173')
        logger.error(f"Callback error: {str(e)}")
        return redirect(f"{frontend_base}/login?error=auth_failed")

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
        now_iso = datetime.now(timezone.utc).isoformat()

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
                "Date": datetime.now(timezone.utc).isoformat(),
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

        # Update transactions in DynamoDB
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

        now = datetime.now(timezone.utc).isoformat()
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
        data["Date"] = datetime.now(timezone.utc).isoformat()

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
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

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
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")
