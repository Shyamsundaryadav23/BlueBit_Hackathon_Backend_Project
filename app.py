import uuid
import datetime
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

# Load environment variables
load_dotenv()

# Configure logging: Set to DEBUG for detailed logs if needed.
# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Updated CORS configuration to allow your frontend origin and necessary methods/headers.
CORS(app,
     supports_credentials=True,
     resources={r"/*": {
         "origins": "*",
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Authorization", "Content-Type"]
     }})

app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# Google OAuth settings
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))

# DynamoDB setup
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)

# Tables (using defaults if not specified in .env)
users_table = dynamodb.Table(os.getenv('DYNAMODB_USERS_TABLE', 'Users'))
groups_table = dynamodb.Table(os.getenv('DYNAMODB_GROUPS_TABLE', 'Groups'))
expenses_table = dynamodb.Table(os.getenv('DYNAMODB_EXPENSES_TABLE', 'Expenses'))
transactions_table = dynamodb.Table(os.getenv('DYNAMODB_TRANSACTIONS_TABLE', 'Transactions'))

def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Bypass token check for preflight requests.
        if request.method == "OPTIONS":
            return jsonify({}), 200

        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        if not token:
            logger.debug("Token is missing in request headers")
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            logger.debug(f"Decoded JWT payload: {data}")
            response = users_table.get_item(Key={"UserID": data['user_id']})
            if "Item" not in response:
                logger.debug("User not found in DynamoDB")
                return jsonify({'message': 'User not found'}), 401
            current_user = response["Item"]
            logger.debug(f"Authenticated user: {current_user}")
        except jwt.ExpiredSignatureError:
            logger.debug("Token has expired")
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            logger.debug("Invalid token provided")
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            return jsonify({'message': 'Error processing token'}), 500
        return f(current_user, *args, **kwargs)
    return decorated

# email verification
@app.route("/api/verify-email", methods=["POST"])
def verify_email():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"success": False, "error": "No token provided"}), 400

    try:
        email = base64.b64decode(token).decode()
    except:
        return jsonify({"success": False, "error": "Invalid token"}), 400

    try:
        response = users_table.update_item(
            Key={"email": email},
            UpdateExpression="SET verified = :val",
            ExpressionAttributeValues={":val": True},
            ReturnValues="UPDATED_NEW"
        )
        return jsonify({"success": True, "message": "Email verified successfully!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def get_google_provider_cfg():
    """Fetch Google OpenID configuration."""
    try:
        cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        logger.debug("Fetched Google provider configuration successfully")
        return cfg
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Google OpenID config: {e}")
        return None

@app.route("/api/login")
def login():
    """Initiate Google OAuth flow using the frontend callback URL."""
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

@app.route("/api/callback")
def callback():
    """Handle OAuth callback from Google: exchange code, update DynamoDB, and generate a JWT."""
    try:
        code = request.args.get("code")
        if not code:
            logger.error("Authorization code missing in callback")
            return jsonify({'error': 'Authorization code missing'}), 400
        
        logger.info(f"Received authorization code: {code}")
        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            return jsonify({'error': 'Unable to fetch Google configuration'}), 500
        
        token_endpoint = google_cfg["token_endpoint"]
        frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:5173/auth/callback")
        logger.debug(f"Using redirect_uri for token exchange: {frontend_callback}")
        
        token_response = requests.post(
            token_endpoint,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": frontend_callback,
                "grant_type": "authorization_code"
            }
        )
        
        if not token_response.ok:
            logger.error(f"Token exchange failed: {token_response.text}")
            return jsonify({'error': 'Failed to retrieve token from Google'}), 400
        
        token_json = token_response.json()
        access_token = token_json.get("access_token")
        logger.debug(f"Access token received: {access_token}")
        
        userinfo_endpoint = google_cfg["userinfo_endpoint"]
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if not userinfo_response.ok:
            logger.error(f"User info fetch failed: {userinfo_response.text}")
            return jsonify({'error': 'Failed to retrieve user information'}), 400
        
        userinfo = userinfo_response.json()
        logger.debug(f"User info: {userinfo}")
        
        if not userinfo.get("email_verified", False):
            logger.error("Email not verified by Google")
            return jsonify({'error': 'Email not verified by Google'}), 400
        
        email = userinfo["email"]
        logger.debug(f"User email: {email}")
        
        query_response = users_table.query(
            IndexName="EmailIndex",
            KeyConditionExpression=Key("Email").eq(email)
        )
        
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if query_response.get("Items"):
            user_record = query_response["Items"][0]
            user_id = user_record["UserID"]
            try:
                users_table.update_item(
                    Key={"UserID": user_id},
                    UpdateExpression="SET #name = :name, picture = :picture, last_login = :last_login",
                    ExpressionAttributeNames={"#name": "name"},
                    ExpressionAttributeValues={
                        ":name": userinfo.get("name", ""),
                        ":picture": userinfo.get("picture", ""),
                        ":last_login": now_iso
                    }
                )
                user_record.update({
                    "name": userinfo.get("name", ""),
                    "picture": userinfo.get("picture", ""),
                    "last_login": now_iso
                })
                logger.info(f"Existing user updated: {email}")
            except Exception as e:
                logger.error(f"DynamoDB update failed: {e}")
                return jsonify({'error': 'Database operation failed'}), 500
        else:
            user_id = str(uuid.uuid4())
            user_record = {
                "UserID": user_id,
                "Email": email,
                "name": userinfo.get("name", ""),
                "picture": userinfo.get("picture", ""),
                "created_at": now_iso,
                "last_login": now_iso
            }
            try:
                users_table.put_item(Item=user_record)
                logger.info(f"New user created: {email} with UserID: {user_id}")
            except Exception as e:
                logger.error(f"DynamoDB put_item failed: {e}")
                return jsonify({'error': 'Database operation failed'}), 500
        
        try:
            exp_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRATION_HOURS)
            payload = {
                'user_id': user_id,
                'exp': exp_time
            }
            token = jwt.encode(payload, app.secret_key, algorithm='HS256')
            logger.debug("JWT token generated successfully")
            return jsonify({
                'token': token,
                'user': user_record,
                'expires': exp_time.isoformat()
            })
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            return jsonify({'error': 'Authentication failed'}), 500
            
    except Exception as e:
        logger.error(f"Callback error: {e}")
        return jsonify({'error': 'Authentication process failed'}), 500

@app.route("/api/user", methods=["GET"])
@token_required
def get_user(current_user):
    """Return the current user profile."""
    logger.debug("Returning current user profile")
    return jsonify(current_user)

@app.route("/api/logout", methods=["POST"])
@token_required
def logout(current_user):
    """Log out the user (for future expansion)."""
    logger.info(f"User logged out: {current_user['Email']}")
    return jsonify({'message': 'Successfully logged out'})

@app.route("/api/dashboard")
@token_required
def dashboard(current_user):
    """Protected dashboard route example."""
    logger.debug("Dashboard accessed by user")
    return jsonify({
        'message': 'You have access to the dashboard',
        'user': current_user
    })

# ----- API endpoints for Groups -----
@app.route("/api/groups", methods=["POST"])
@token_required
def create_group(current_user):
    """Create a new group, automatically associating it with the current user."""
    try:
        data = request.get_json()
        if not data or "name" not in data:
            logger.error("Group name is required")
            return jsonify({'error': 'Group name is required'}), 400
        
        # Generate a unique GroupID and record creation timestamp
        group_id = str(uuid.uuid4())
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Create the group with current user as creator and add them to members
        group_data = {
            "GroupID": group_id,
            "name": data.get("name"),
            "createdBy": current_user.get("Email"),
            "members": data.get("members", []),
            "createdAt": now_iso
        }
        # Ensure current user is included in the members list
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
    """Fetch group by GroupID only if current user is the creator or a member."""
    try:
        logger.debug(f"Fetching group with GroupID: {group_id}")
        response = groups_table.get_item(Key={"GroupID": group_id})
        if "Item" not in response:
            logger.error("Group not found")
            return jsonify({'error': 'Group not found'}), 404
        
        group = response["Item"]
        user_email = current_user.get("Email")
        # Check if user is creator or member
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
    """
    Fetch all groups for which the current user is either the creator or a member.
    """
    try:
        logger.debug("Scanning all groups from DynamoDB")
        response = groups_table.scan()
        all_groups = response.get('Items', [])
        
        user_email = current_user.get('Email')
        
        filtered_groups = []
        for group in all_groups:
            created_by = group.get('createdBy')
            members = group.get('members', [])
            
            # Include if current user created the group
            if created_by == user_email:
                filtered_groups.append(group)
                continue
            
            # Include if current user is a member
            if any(member.get('email') == user_email for member in members):
                filtered_groups.append(group)
        
        if not filtered_groups:
            logger.error("No groups found for this user")
            return jsonify({'error': 'No groups found'}), 404
        
        logger.info("Groups retrieved successfully for this user")
        return jsonify(filtered_groups), 200

    except Exception as e:
        logger.error(f"Error fetching groups: {e}")
        return jsonify({'error': 'Failed to fetch groups'}), 500

# ----- API endpoints for Expenses -----

# Helper function: recursively convert floats to Decimals
def convert_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, list):
        return [convert_to_decimal(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_to_decimal(value) for key, value in obj.items()}
    else:
        return obj
    

@app.route("/api/expenses", methods=["POST", "OPTIONS"])
@token_required
def create_expense(current_user):
    """Create a new expense for a specific group, only if the user is authorized."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        data = request.get_json()
        logger.debug(f"Received expense data: {data}")
        # Accept either "groupId" or "GroupID" from the request
        group_id = data.get("groupId") or data.get("GroupID")
        if not data or "ExpenseID" not in data or not group_id:
            logger.error("ExpenseID or groupId missing in request")
            return jsonify({'error': 'ExpenseID and groupId are required'}), 400

        # Validate group and user membership
        group_response = groups_table.get_item(Key={"GroupID": group_id})
        if "Item" not in group_response:
            logger.error("Group not found for provided groupId")
            return jsonify({'error': 'Group not found'}), 404

        group_item = group_response["Item"]
        user_email = current_user.get("Email")
        if group_item.get("createdBy") != user_email and not any(member.get("email") == user_email for member in group_item.get("members", [])):
            logger.error("User not authorized to add expense to this group")
            return jsonify({'error': 'User not authorized for this group'}), 403

        # Add a createdAt timestamp if not provided
        if "createdAt" not in data:
            data["createdAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            logger.debug("Added createdAt timestamp to expense data")

        # Ensure consistent attribute for the group ID
        data["GroupID"] = group_id

        # Convert any float values in the data to Decimal
        converted_data = convert_to_decimal(data)

        # Use a ConditionExpression to ensure ExpenseID uniqueness (optional)
        expenses_table.put_item(
            Item=converted_data,
            ConditionExpression="attribute_not_exists(ExpenseID)"
        )
        logger.info("Expense created successfully")
        return jsonify({'message': 'Expense created successfully', 'expense': data}), 201
    except Exception as e:
        logger.error(f"Error creating expense: {repr(e)}")
        return jsonify({'error': 'Failed to create expense', 'details': str(e)}), 500


@app.route("/api/expenses/group/<group_id>", methods=["GET", "OPTIONS"])
@token_required
def get_expenses_by_group(current_user, group_id):
    """Fetch all expenses for a specific group id, only if the current user is authorized (i.e. is the creator or a member of the group)."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        # Retrieve group details from DynamoDB.
        group_response = groups_table.get_item(Key={"GroupID": group_id})
        if "Item" not in group_response:
            logger.error("Group not found")
            return jsonify({'error': 'Group not found'}), 404
        
        group_item = group_response["Item"]
        # Use the correct key "Email" for the current user.
        user_email = current_user.get("Email")
        
        # Check if the current user is the creator or a member of the group.
        if group_item.get("createdBy") != user_email and not any(member.get("email") == user_email for member in group_item.get("members", [])):
            logger.error("User not authorized to view expenses for this group")
            return jsonify({'error': 'User not authorized for this group'}), 403

        # Now, fetch expenses that belong to this group.
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

# ----- API endpoints for Transactions -----
@app.route("/api/transactions", methods=["POST"])
@token_required
def create_transaction(current_user):
    """Create a new transaction."""
    try:
        data = request.get_json()
        logger.debug(f"Received transaction data: {data}")
        if not data or "TransactionID" not in data or "GroupID" not in data:
            logger.error("TransactionID and GroupID are required for transaction creation")
            return jsonify({'error': 'TransactionID and GroupID are required'}), 400
        transactions_table.put_item(Item=data)
        logger.info("Transaction created successfully")
        return jsonify({'message': 'Transaction created successfully', 'transaction': data}), 201
    except Exception as e:
        logger.error(f"Error creating transaction: {e}")
        return jsonify({'error': 'Failed to create transaction'}), 500

@app.route("/api/transactions/<transaction_id>", methods=["GET"])
@token_required
def get_transaction(current_user, transaction_id):
    """Fetch transaction by TransactionID."""
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
    """Fetch transactions by GroupID using the Global Secondary Index."""
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

# ----- Error Handlers -----
@app.errorhandler(404)
def not_found(e):
    logger.error("404 Not Found: Resource not found")
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 Internal Server Error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == "__main__":
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("Google OAuth credentials not set in environment variables")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
