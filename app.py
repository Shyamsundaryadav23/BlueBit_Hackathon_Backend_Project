import eventlet
eventlet.monkey_patch()
import uuid
from datetime import datetime, timezone, timedelta
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
         "origins": [
             "http://localhost:5173",
             "https://splitbro.vercel.app"
         ],
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Authorization", "Content-Type"]
     }})

app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# Initialize SocketIO for real-time chat with Eventlet
socketio = SocketIO(app, 
                   cors_allowed_origins=[
                       "http://localhost:5173",
                       "https://splitbro.vercel.app"
                   ],
                   async_mode="eventlet")

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

# Helper function: recursively convert floats to Decimals
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

# ------------------------
# OCR Functions and Routes
# ------------------------

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_details_from_receipt(image_path):
    image = Image.open(image_path)
    ocr_text = pytesseract.image_to_string(image)

    shop_name = "Dmart" if "DMART" in ocr_text.upper() else "Unknown"
    
    date_pattern = r'(\d{2}[/\-]\d{2}[/\-]\d{4})'
    date_match = re.search(date_pattern, ocr_text)
    date = date_match.group(0) if date_match else "Date not found"

    total_pattern = r'Total\s*[:Rs.]\s([\d.,]+)'
    total_match = re.search(total_pattern, ocr_text)
    total_amount = f"Rs. {total_match.group(1)}" if total_match else "Total not found"

    items = []
    item_pattern = re.compile(
        r'(\d{6,})\s+([A-Z0-9\s\-?\/,.&]+)\s+[-~]\s*(\d+)\s+([\d.]+)\s+([\d.]+)'
    )

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

@app.route('/api/ocr/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if allowed_file(file.filename):
        filename = os.path.basename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        results = extract_details_from_receipt(filepath)
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
    try:
        data = request.json
        email = base64.b64decode(data.get("token")).decode()
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
            ExpressionAttributeValues={":val": True}
        )
        return jsonify({"success": True, "message": "Email verified successfully!"})
    except Exception as e:
        logger.error(f"verify_email error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

def get_google_provider_cfg():
    try:
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Google config: {e}")
        return None

@app.route("/api/login")
def login():
    try:
        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            return jsonify({'error': 'Google config unavailable'}), 500
            
        request_uri = requests.Request(
            'GET',
            google_cfg["authorization_endpoint"],
            params={
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": os.getenv("FRONTEND_CALLBACK_URL"),
                "scope": "openid email profile",
                "response_type": "code",
                "access_type": "offline",
                "prompt": "consent"
            }
        ).prepare().url
        return redirect(request_uri)
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route("/api/callback")
def callback():
    try:
        code = request.args.get("code")
        if not code:
            return jsonify({'error': 'Missing authorization code'}), 400

        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            return jsonify({'error': 'Google config unavailable'}), 500

        token_response = requests.post(
            google_cfg["token_endpoint"],
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": os.getenv("FRONTEND_CALLBACK_URL"),
                "grant_type": "authorization_code"
            }
        )
        if not token_response.ok:
            logger.error(f"Token exchange failed: {token_response.text}")
            return jsonify({'error': 'Failed to get access token'}), 400

        access_token = token_response.json().get("access_token")
        userinfo = requests.get(
            google_cfg["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()

        if not userinfo.get("email_verified", False):
            return jsonify({'error': 'Email not verified'}), 400

        email = userinfo["email"]
        response = users_table.query(
            IndexName="EmailIndex",
            KeyConditionExpression=Key("Email").eq(email)
        )
        
        now_iso = datetime.now(timezone.utc).isoformat()
        if response.get("Items"):
            user = response["Items"][0]
            users_table.update_item(
                Key={"UserID": user["UserID"]},
                UpdateExpression="SET #name = :name, picture = :picture, last_login = :last_login",
                ExpressionAttributeNames={"#name": "name"},
                ExpressionAttributeValues={
                    ":name": userinfo.get("name", ""),
                    ":picture": userinfo.get("picture", ""),
                    ":last_login": now_iso
                }
            )
        else:
            user_id = str(uuid.uuid4())
            user = {
                "UserID": user_id,
                "Email": email,
                "name": userinfo.get("name", ""),
                "picture": userinfo.get("picture", ""),
                "created_at": now_iso,
                "last_login": now_iso
            }
            users_table.put_item(Item=user)

        exp_time = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
        token = jwt.encode({
            'user_id': user["UserID"],
            'exp': exp_time
        }, app.secret_key, algorithm='HS256')

        return jsonify({
            'token': token,
            'user': user,
            'expires': exp_time.isoformat()
        })
    except Exception as e:
        logger.error(f"Callback error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route("/api/user", methods=["GET"])
@token_required
def get_user(current_user):
    return jsonify(current_user)

@app.route("/api/logout", methods=["POST"])
@token_required
def logout(current_user):
    return jsonify({'message': 'Logged out successfully'})

@app.route("/api/dashboard")
@token_required
def dashboard(current_user):
    return jsonify({'user': current_user})

# ------------------------
# Groups Endpoints
# ------------------------

@app.route("/api/groups", methods=["POST"])
@token_required
def create_group(current_user):
    try:
        data = request.get_json()
        if not data.get("name"):
            return jsonify({'error': 'Group name required'}), 400
            
        group_id = str(uuid.uuid4())
        group_data = {
            "GroupID": group_id,
            "name": data["name"],
            "createdBy": current_user["Email"],
            "members": data.get("members", []),
            "createdAt": datetime.now(timezone.utc).isoformat()
        }
        
        if not any(m["email"] == current_user["Email"] for m in group_data["members"]):
            group_data["members"].append({"email": current_user["Email"]})
            
        groups_table.put_item(Item=group_data)
        return jsonify({'message': 'Group created', 'group': group_data}), 201
    except Exception as e:
        logger.error(f"Group creation error: {e}")
        return jsonify({'error': 'Failed to create group'}), 500

@app.route("/api/groups/<group_id>", methods=["GET"])
@token_required
def get_group(current_user, group_id):
    try:
        group = groups_table.get_item(Key={"GroupID": group_id}).get("Item")
        if not group:
            return jsonify({'error': 'Group not found'}), 404
            
        user_email = current_user["Email"]
        if group["createdBy"] != user_email and not any(m["email"] == user_email for m in group.get("members", [])):
            return jsonify({'error': 'Unauthorized'}), 403
            
        return jsonify(group)
    except Exception as e:
        logger.error(f"Group fetch error: {e}")
        return jsonify({'error': 'Failed to fetch group'}), 500

@app.route("/api/groups", methods=["GET"])
@token_required
def get_all_groups(current_user):
    try:
        groups = groups_table.scan().get('Items', [])
        filtered = [
            g for g in groups
            if g["createdBy"] == current_user["Email"] or 
            any(m["email"] == current_user["Email"] for m in g.get("members", []))
        ]
        return jsonify(filtered)
    except Exception as e:
        logger.error(f"Groups fetch error: {e}")
        return jsonify({'error': 'Failed to fetch groups'}), 500

# ------------------------
# Error Handlers
# ------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/health')
def health_check():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)