Expense Tracker 
Backend API
A Flask-based backend API for an Expense Tracker app featuring:

Google OAuth 2.0 authentication with JWT tokens

User, Group, Expense, Transaction, and Chat management using AWS DynamoDB

Receipt OCR scanning powered by Tesseract

Real-time communication via WebSockets (SocketIO)

Secure session and CORS handling

Table of Contents
Features

Tech Stack

Setup & Installation

Environment Variables

Running the Server

API Endpoints

Authentication Flow

OCR Functionality

Real-time Communication

Error Handling & Logging

License

Features
Google OAuth 2.0 Login: Secure login using Google accounts with PKCE

JWT Authentication: Token-based secure API access

DynamoDB Integration: Manage users, groups, expenses, transactions, and chats

Receipt OCR: Upload images and extract details using Tesseract OCR

SocketIO: Real-time updates and chat messaging

CORS & Session Management: Configured for frontend-backend communication

Tech Stack
Python 3.x

Flask & Flask-SocketIO

AWS DynamoDB (via boto3)

JWT (PyJWT)

Gevent for async concurrency

Tesseract OCR & Pillow for image processing

dotenv for environment config

Requests for HTTP calls

Setup & Installation
Clone the repository


git clone https://github.com/yourusername/expense-tracker-backend.git
cd expense-tracker-backend
Create a virtual environment


python -m venv venv
venv\Scripts\activate  # Windows
Install dependencies


pip install -r requirements.txt
Install Tesseract OCR

Ubuntu/Debian:


sudo apt-get install tesseract-ocr
macOS (with Homebrew):


brew install tesseract
Windows:

Download from https://github.com/tesseract-ocr/tesseract/wiki and add to PATH.

Environment Variables
Create a .env file in the root directory with the following:


SECRET_KEY=your_secret_key_here
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
BACKEND_CALLBACK_URL=http://localhost:5000/api/callback
FRONTEND_BASE_URL=http://localhost:5173
JWT_EXPIRATION_HOURS=24
AWS_REGION=your_aws_region
DYNAMODB_USERS_TABLE=Users
DYNAMODB_GROUPS_TABLE=Groups
DYNAMODB_EXPENSES_TABLE=Expenses
DYNAMODB_TRANSACTIONS_TABLE=Transactions
DYNAMODB_CHATS_TABLE=Chats
Make sure AWS credentials are configured either via environment variables or AWS CLI.

Running the Server

export FLASK_APP=app.py
export FLASK_ENV=development  # Optional: enables debug mode
flask run
Or with SocketIO support using gevent:

python -m gevent app.py
API Endpoints
Authentication
GET /api/login - Redirects to Google OAuth login

GET /api/callback - Google OAuth callback URL

GET /api/user - Get current logged-in user profile (JWT required)

POST /api/logout - Logout current user (JWT required)

OCR
POST /api/ocr/upload - Upload receipt image for OCR extraction (JWT required)

GET /api/ocr/scan - Check OCR API status and allowed file formats (JWT required)

Groups
POST /api/groups - Create a new group (JWT required)

GET /api/groups/<group_id> - Get group details (JWT required)

PUT /api/groups/<group_id> - Update group (JWT required)

DELETE /api/groups/<group_id> - Delete group (JWT required)

GET /api/groups - List groups for current user (JWT required)

Expenses, Transactions, Chats, Dashboard
(Include descriptions and routes as implemented)

Authentication Flow
User accesses /api/login and is redirected to Google OAuth consent screen.

After consent, Google redirects to /api/callback with an authorization code.

Backend exchanges code for access token, fetches user info, and stores/updates user in DynamoDB.

JWT token is created and sent back to frontend in URL fragment.

Frontend includes JWT token in Authorization header for subsequent API requests.

OCR Functionality
Upload image files (png, jpg, jpeg) at /api/ocr/upload with JWT authorization.

Backend extracts shop name, date, total amount, and items from receipt using Tesseract OCR.

Returns JSON with extracted details.

Real-time Communication
SocketIO initialized with Gevent async mode.

Supports rooms, join/leave events, and message broadcasting (customize as per your app’s needs).

Error Handling & Logging
Standardized JSON error responses with appropriate HTTP status codes.

Logging configured at WARNING level by default, debug logs available for deeper inspection.

