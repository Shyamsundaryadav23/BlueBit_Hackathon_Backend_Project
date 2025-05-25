🧾 Expense Tracker – Backend API
A Flask-based backend API for the SplitBro Expense Tracker app, featuring real-time communication, OCR-based receipt scanning, secure authentication, and group/expense management.

📑 Table of Contents
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

✨ Features
🔐 Google OAuth 2.0 Login with PKCE for secure authentication

🔑 JWT Authentication for token-based access

🧾 Receipt OCR powered by Tesseract for automated data extraction

🧑‍🤝‍🧑 User, Group, Expense, Transaction, and Chat Management via AWS DynamoDB

📡 Real-time Communication with WebSockets (SocketIO)

🌐 CORS & secure Session Handling for frontend-backend integration

🛠️ Tech Stack
Language: Python 3.x

Frameworks: Flask, Flask-SocketIO

Database: AWS DynamoDB (boto3)

Authentication: Google OAuth 2.0, JWT (PyJWT)

OCR: Tesseract OCR, Pillow

Concurrency: Gevent

Config: python-dotenv

Utilities: Requests

⚙️ Setup & Installation
1. Clone the Repository

git clone https://github.com/yourusername/expense-tracker-backend.git
cd expense-tracker-backend
2. Create a Virtual Environment

python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
3. Install Dependencies

pip install -r requirements.txt
4. Install Tesseract OCR
Ubuntu/Debian:


sudo apt-get install tesseract-ocr
macOS (Homebrew):


brew install tesseract
Windows:
Download from Tesseract GitHub Wiki and add it to your system PATH.

🔐 Environment Variables
Create a .env file in the root directory with the following:

env
Copy
Edit
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
✅ Ensure your AWS credentials are configured (via ~/.aws/credentials or environment variables).

🚀 Running the Server
Option 1: Standard Flask

export FLASK_APP=app.py
export FLASK_ENV=development  # Optional for debug mode
flask run
Option 2: With WebSocket Support (Gevent)

python -m gevent app.py
📡 API Endpoints
🔐 Authentication
GET /api/login – Redirects to Google OAuth login

GET /api/callback – Handles the OAuth callback

GET /api/user – Get the current logged-in user (JWT required)

POST /api/logout – Log out the current user (JWT required)

🧾 OCR (Receipt Scanning)
POST /api/ocr/upload – Upload receipt for OCR (JWT required)

GET /api/ocr/scan – Check OCR API status and allowed file types (JWT required)

👥 Groups
POST /api/groups – Create a group (JWT required)

GET /api/groups/<group_id> – Get group details (JWT required)

PUT /api/groups/<group_id> – Update group (JWT required)

DELETE /api/groups/<group_id> – Delete group (JWT required)

GET /api/groups – List all groups for the user (JWT required)

💰 Expenses, Transactions, Chats, Dashboard
(Add detailed routes and their usage as implemented in your code)

🔄 Authentication Flow
User initiates login via GET /api/login.

Redirected to Google OAuth consent screen.

After consent, redirected back to GET /api/callback.

Backend exchanges code for user info and creates JWT token.

JWT returned to frontend and stored securely.

JWT is sent in Authorization header for all future API calls.

🧾 OCR Functionality
Upload PNG, JPG, or JPEG receipts using POST /api/ocr/upload.

Backend uses Tesseract OCR to extract:

Shop name

Date

Total amount

Itemized list

Returns a JSON response with structured expense data.

🔴 Real-time Communication (WebSockets)
Powered by Socket.IO with Gevent for async.

Custom events supported:

Join/Leave group rooms

Broadcast new messages/expenses

Ideal for real-time notifications and chat.

⚠️ Error Handling & Logging
All endpoints return standardized JSON error messages.

HTTP status codes reflect errors (400, 401, 403, 500).

Logs enabled at WARNING level by default.

Optional debug-level logs for development.

