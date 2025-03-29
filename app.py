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
from collections import defaultdict

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

# Tables
users_table = dynamodb.Table(os.getenv('DYNAMODB_USERS_TABLE', 'Users'))
groups_table = dynamodb.Table(os.getenv('DYNAMODB_GROUPS_TABLE', 'Groups'))
expenses_table = dynamodb.Table(os.getenv('DYNAMODB_EXPENSES_TABLE', 'Expenses'))
transactions_table = dynamodb.Table(os.getenv('DYNAMODB_TRANSACTIONS_TABLE', 'Transactions'))

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

@app.route("/api/callback")
def callback():
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
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
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

# Debt Settlement Endpoint
@app.route("/api/groups/<group_id>/settle", methods=["POST"])
@token_required
def settle_group_debts(current_user, group_id):
    try:
        # Fetch group details and check authorization
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

        # Compute net balance for each member.
        # Positive balance: member should receive money.
        # Negative balance: member should pay money.
        balances = defaultdict(Decimal)
        # Consider only members with valid email.
        member_emails = {m["email"] for m in group.get("members", []) if m.get("email")}
        for email in member_emails:
            balances[email] = Decimal('0')

        for expense in expenses:
            paid_by = expense["paidBy"]
            # For each split, deduct from the participant and add to the payer.
            for split in expense.get("splits", []):
                # Unwrap DynamoDB format if needed.
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
                # If the participant is not the payer, update net balances.
                if member_id != paid_by:
                    balances[member_id] -= amount
                    balances[paid_by] += amount

        # Define a recursive function to minimize cash flow.
        def min_cash_flow(bal_list):
            # Base condition: if all balances are effectively zero, return empty list.
            if all(abs(b) < Decimal("0.01") for _, b in bal_list):
                return []
            # Find maximum creditor and maximum debtor.
            max_creditor = max(bal_list, key=lambda x: x[1])
            max_debtor = min(bal_list, key=lambda x: x[1])
            # Settle amount is the minimum of what the creditor is owed and what the debtor owes.
            settle_amt = min(max_creditor[1], -max_debtor[1])
            # Prepare a transaction: debtor pays settle_amt to creditor.
            txn = {
                "TransactionID": str(uuid.uuid4()),
                "GroupID": group_id,
                "From": max_debtor[0],
                "To": max_creditor[0],
                "Amount": settle_amt,
                "Date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "Status": "pending",
                "CreatedBy": current_user["UserID"]
            }
            # Update balances.
            new_bal_list = []
            for email, bal in bal_list:
                if email == max_creditor[0]:
                    new_bal_list.append((email, bal - settle_amt))
                elif email == max_debtor[0]:
                    new_bal_list.append((email, bal + settle_amt))
                else:
                    new_bal_list.append((email, bal))
            # Recursively settle remaining amounts.
            return [txn] + min_cash_flow(new_bal_list)

        # Convert the balances dict into a list of tuples.
        balance_list = list(balances.items())
        transactions = min_cash_flow(balance_list)

        # Clear any existing transactions for this group.
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

# @app.route("/api/expenses", methods=["POST", "OPTIONS"])
# @token_required
# def create_expense(current_user):
#     if request.method == "OPTIONS":
#         return jsonify({}), 200
        
#     try:
#         data = request.get_json()
#         group_id = data.get("groupId") or data.get("GroupID")
#         if not data or not group_id:
#             return jsonify({'error': 'Invalid request'}), 400

#         group = groups_table.get_item(Key={"GroupID": group_id}).get("Item")
#         if not group:
#             return jsonify({'error': 'Group not found'}), 404
            
#         user_email = current_user["Email"]
#         if group["createdBy"] != user_email and not any(m["email"] == user_email for m in group["members"]):
#             return jsonify({'error': 'Unauthorized'}), 403

#         now = datetime.datetime.now(datetime.timezone.utc).isoformat()
#         data.update({
#             "createdBy": current_user["UserID"],
#             "paidBy": user_email,
#             "createdAt": now,
#             "updatedAt": now,
#             "GroupID": group_id
#         })

#         if "amount" in data:
#             data["amount"] = Decimal(str(data["amount"]))
#         if "splits" in data:
#             for split in data["splits"]:
#                 split["amount"] = Decimal(str(split["amount"]))

#         expenses_table.put_item(Item=data)
#         return jsonify({'message': 'Expense created', 'expense': data}), 201

#     except Exception as e:
#         logger.error(f"Expense error: {str(e)}")
#         return jsonify({'error': 'Failed to create expense'}), 500
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
            
        user_email = current_user.get("Email")
        if not user_email:
            return jsonify({'error': 'Current user email not found'}), 400

        # Check authorization: current user's email must be in group's members or be the creator.
        if group["createdBy"] != user_email and not any(m.get("email") == user_email for m in group.get("members", [])):
            return jsonify({'error': 'Unauthorized'}), 403

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data.update({
            "createdBy": current_user["UserID"],
            "paidBy": user_email,  # You may later want to store the userID instead
            "createdAt": now,
            "updatedAt": now,
            "GroupID": group_id
        })

        # Convert amount and update splits to use the actual UserID from Users table.
        if "amount" in data:
            data["amount"] = Decimal(str(data["amount"]))
        if "splits" in data:
            for split in data["splits"]:
                # We assume split["memberId"] is an email.
                member_email = split.get("memberId")
                if not member_email:
                    # Skip or handle missing email as needed.
                    logger.error("Split entry missing member email.")
                    split["memberId"] = ""
                    continue
                # Query Users table via the EmailIndex
                user_query = users_table.query(
                    IndexName="EmailIndex",
                    KeyConditionExpression=Key("Email").eq(member_email)
                )
                if "Items" in user_query and len(user_query["Items"]) > 0:
                    split["memberId"] = user_query["Items"][0]["UserID"]
                else:
                    logger.error(f"User with email {member_email} not found in Users table.")
                    split["memberId"] = ""
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
        data["Date"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
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

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")
