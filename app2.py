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

# Load environment variables
load_dotenv()

# Configure logging: Set to DEBUG for detailed logs.
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})
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
    """Decorator to require a valid JWT token for protected routes."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
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

@app.route("/api/health")
def health_check():
    """Health check endpoint."""
    logger.debug("Health check endpoint called")
    return jsonify({'status': 'healthy'})

# ----- API endpoints for Groups -----
@app.route("/api/groups", methods=["POST"])
@token_required
def create_group(current_user):
    """Create a new group."""
    try:
        data = request.get_json()
        logger.debug(f"Received group data: {data}")
        if not data or "GroupID" not in data:
            logger.error("GroupID is required but not provided")
            return jsonify({'error': 'GroupID is required'}), 400
        groups_table.put_item(Item=data)
        logger.info("Group created successfully")
        return jsonify({'message': 'Group created successfully', 'group': data}), 201
    except Exception as e:
        logger.error(f"Error creating group: {e}")
        return jsonify({'error': 'Failed to create group'}), 500

@app.route("/api/groups/<group_id>", methods=["GET"])
@token_required
def get_group(current_user, group_id):
    """Fetch group by GroupID."""
    try:
        logger.debug(f"Fetching group with GroupID: {group_id}")
        response = groups_table.get_item(Key={"GroupID": group_id})
        if "Item" not in response:
            logger.error("Group not found")
            return jsonify({'error': 'Group not found'}), 404
        logger.debug("Group found, returning group data")
        return jsonify(response["Item"])
    except Exception as e:
        logger.error(f"Error fetching group: {e}")
        return jsonify({'error': 'Failed to fetch group'}), 500

@app.route("/api/groups", methods=["GET"])
@token_required
def get_all_groups(current_user):
    """Fetch all groups."""
    try:
        logger.debug("Scanning all groups from DynamoDB")
        response = groups_table.scan()
        if 'Items' not in response or len(response['Items']) == 0:
            logger.error("No groups found")
            return jsonify({'error': 'No groups found'}), 404
        logger.info("Groups retrieved successfully")
        return jsonify(response['Items']), 200
    except Exception as e:
        logger.error(f"Error fetching groups: {e}")
        return jsonify({'error': 'Failed to fetch groups'}), 500

# ----- API endpoints for Expenses -----
@app.route("/api/expenses", methods=["POST"])
@token_required
def create_expense(current_user):
    """Create a new expense for a specific group."""
    try:
        data = request.get_json()
        logger.debug(f"Received expense data: {data}")
        if not data or "ExpenseID" not in data or "groupId" not in data:
            logger.error("ExpenseID or groupId missing in request")
            return jsonify({'error': 'ExpenseID and groupId are required'}), 400

        logger.debug(f"Validating group with GroupID: {data['groupId']}")
        group_response = groups_table.get_item(Key={"GroupID": data["groupId"]})
        if "Item" not in group_response:
            logger.error("Group not found for provided groupId")
            return jsonify({'error': 'Group not found'}), 404

        # Log emails of all members from the group (if available)
        group_item = group_response["Item"]
        if "members" in group_item and group_item["members"]:
            for member in group_item["members"]:
                logger.debug(f"Group member email: {member.get('email')}")
        else:
            logger.debug("No members found in the group")

        if "createdAt" not in data:
            data["createdAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            logger.debug("Added createdAt timestamp to expense data")

        expenses_table.put_item(Item=data)
        logger.info("Expense created successfully")
        return jsonify({'message': 'Expense created successfully', 'expense': data}), 201
    except Exception as e:
        logger.error(f"Error creating expense: {e}")
        return jsonify({'error': 'Failed to create expense'}), 500

@app.route("/api/expenses/<expense_id>", methods=["GET"])
@token_required
def get_expense(current_user, expense_id):
    """Fetch expense by ExpenseID."""
    try:
        logger.debug(f"Fetching expense with ExpenseID: {expense_id}")
        response = expenses_table.get_item(Key={"ExpenseID": expense_id})
        if "Item" not in response:
            logger.error("Expense not found")
            return jsonify({'error': 'Expense not found'}), 404
        logger.info("Expense fetched successfully")
        return jsonify(response["Item"])
    except Exception as e:
        logger.error(f"Error fetching expense: {e}")
        return jsonify({'error': 'Failed to fetch expense'}), 500

@app.route("/api/get/expenses", methods=["GET"])
@token_required
def get_all_expenses(current_user):
    """Fetch all expenses for groups the user belongs to."""
    try:
        logger.debug("Fetching groups for current user")
        groups = []
        last_evaluated_key = None

        while True:
            scan_kwargs = {
                "FilterExpression": Attr("members").contains(current_user["UserID"])
            }
            if last_evaluated_key:
                scan_kwargs["ExclusiveStartKey"] = last_evaluated_key

            response = groups_table.scan(**scan_kwargs)
            groups.extend(response.get("Items", []))
            last_evaluated_key = response.get("LastEvaluatedKey")
            if not last_evaluated_key:
                break

        logger.debug(f"Groups for user: {groups}")

        group_ids = [group["GroupID"] for group in groups]
        logger.debug(f"Extracted group IDs: {group_ids}")

        if not group_ids:
            logger.info("No groups found for user")
            return jsonify([]), 200

        expenses = []
        for group_id in group_ids:
            last_evaluated_key = None
            while True:
                scan_kwargs = {
                    "FilterExpression": Attr("groupId").eq(group_id)
                }
                if last_evaluated_key:
                    scan_kwargs["ExclusiveStartKey"] = last_evaluated_key

                response = expenses_table.scan(**scan_kwargs)
                expenses.extend(response.get("Items", []))
                last_evaluated_key = response.get("LastEvaluatedKey")
                if not last_evaluated_key:
                    break

        logger.info("Expenses fetched successfully for user's groups")
        return jsonify(expenses), 200

    except Exception as e:
        logger.error(f"Error fetching expenses: {str(e)}")
        return jsonify({"error": "Failed to fetch expenses"}), 500

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
