from flask import Flask, redirect, request, jsonify
from flask_cors import CORS
import boto3
from boto3.dynamodb.conditions import Key
import requests
import os
import jwt
import datetime
import functools
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
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
users_table = dynamodb.Table(os.getenv('DYNAMODB_USERS_TABLE', 'Users'))

def token_required(f):
    """Decorator to require a valid JWT token for protected routes."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            response = users_table.get_item(Key={"email": data['user']})
            if "Item" not in response:
                return jsonify({'message': 'User not found'}), 401
            current_user = response["Item"]
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            return jsonify({'message': 'Error processing token'}), 500
        return f(current_user, *args, **kwargs)
    return decorated

def get_google_provider_cfg():
    """Fetch Google OpenID configuration."""
    try:
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Google OpenID config: {e}")
        return None

@app.route("/api/login")
def login():
    """Initiate Google OAuth flow using the frontend callback URL."""
    try:
        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            return jsonify({'error': 'Unable to fetch Google configuration'}), 500
        
        authorization_endpoint = google_cfg["authorization_endpoint"]
        # Use FRONTEND_CALLBACK_URL from environment variables.
        frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:5173/auth/callback")
        logger.info(f"Using FRONTEND_CALLBACK_URL for OAuth: {frontend_callback}")
        
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
        # Retrieve the authorization code from the query string.
        code = request.args.get("code")
        if not code:
            return jsonify({'error': 'Authorization code missing'}), 400
        
        logger.info(f"Received code: {code}")
        google_cfg = get_google_provider_cfg()
        if not google_cfg:
            return jsonify({'error': 'Unable to fetch Google configuration'}), 500
        
        token_endpoint = google_cfg["token_endpoint"]
        # Use the same frontend callback URL for token exchange.
        frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:5173/auth/callback")
        logger.info(f"Using redirect_uri for token exchange: {frontend_callback}")
        
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
        
        # Fetch user info from Google.
        userinfo_endpoint = google_cfg["userinfo_endpoint"]
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if not userinfo_response.ok:
            logger.error(f"User info fetch failed: {userinfo_response.text}")
            return jsonify({'error': 'Failed to retrieve user information'}), 400
        
        userinfo = userinfo_response.json()
        
        if not userinfo.get("email_verified", False):
            return jsonify({'error': 'Email not verified by Google'}), 400
        
        email = userinfo["email"]
        
        # Create or update user in DynamoDB.
        try:
            response = users_table.get_item(Key={"email": email})
            user_data = {
                "email": email,
                "name": userinfo.get("name", ""),
                "picture": userinfo.get("picture", ""),
                "last_login": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            if "Item" not in response:
                user_data["created_at"] = user_data["last_login"]
                users_table.put_item(Item=user_data)
                logger.info(f"New user created: {email}")
            else:
                users_table.update_item(
                    Key={"email": email},
                    UpdateExpression="SET #name = :name, picture = :picture, last_login = :last_login",
                    ExpressionAttributeNames={"#name": "name"},
                    ExpressionAttributeValues={
                        ":name": user_data["name"],
                        ":picture": user_data["picture"],
                        ":last_login": user_data["last_login"]
                    }
                )
                user_data = {**response["Item"], **user_data}
                logger.info(f"Existing user updated: {email}")
        except Exception as e:
            logger.error(f"DynamoDB operation failed: {e}")
            return jsonify({'error': 'Database operation failed'}), 500
        
        # Generate a JWT token.
        try:
            exp_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRATION_HOURS)
            payload = {
                'user': email,
                'exp': exp_time
            }
            token = jwt.encode(payload, app.secret_key, algorithm='HS256')
            return jsonify({
                'token': token,
                'user': user_data,
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
    return jsonify(current_user)

@app.route("/api/logout", methods=["POST"])
@token_required
def logout(current_user):
    """Log out the user (for future expansion)."""
    logger.info(f"User logged out: {current_user['email']}")
    return jsonify({'message': 'Successfully logged out'})

@app.route("/api/dashboard")
@token_required
def dashboard(current_user):
    """Protected dashboard route example."""
    return jsonify({
        'message': 'You have access to the dashboard',
        'user': current_user
    })

@app.route("/api/health")
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'})

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == "__main__":
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("Google OAuth credentials not set in environment variables")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)