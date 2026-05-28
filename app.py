from flask import Flask, request, render_template, redirect
from pymongo import MongoClient
from datetime import datetime
import requests
import os
from dotenv import load_dotenv
import certifi

# ---------------- LOAD ENV ---------------- #

load_dotenv()

app = Flask(__name__)

# ---------------- MONGODB ---------------- #

try:

    client = MongoClient(

        os.getenv("MONGO_URI"),

        tlsCAFile=certifi.where(),

        serverSelectionTimeoutMS=5000

    )

    # Test connection
    client.admin.command('ping')

    print("MongoDB Connected!")

    db = client["falconeye"]

    collection = db["logs"]

except Exception as e:

    print("MongoDB Error:", e)

# ---------------- SQL INJECTION DETECTION ---------------- #

def detect_sqli(text):

    patterns = [

        "'",

        "--",

        " OR ",

        "1=1",

        "DROP",

        "SELECT"

    ]

    return any(
        p.lower() in text.lower()
        for p in patterns
    )

# ---------------- GEO LOCATION ---------------- #

def get_location(ip):

    try:

        # Localhost/private IP handling
        if ip.startswith("127.") or ip.startswith("10."):

            return {

                "country": "Localhost",

                "city": "Private Network",

                "isp": "Local ISP"

            }

        response = requests.get(

            f"http://ip-api.com/json/{ip}",

            timeout=3

        )

        data = response.json()

        return {

            "country": data.get("country", "Unknown"),

            "city": data.get("city", "Unknown"),

            "isp": data.get("isp", "Unknown")

        }

    except Exception as e:

        print("Location Error:", e)

        return {

            "country": "Unknown",

            "city": "Unknown",

            "isp": "Unknown"

        }

# ---------------- HOME PAGE ---------------- #

@app.route('/')
def home():

    return render_template("index.html")

# ---------------- LOGIN PAGE ---------------- #

@app.route('/login_page')
def login_page():

    return render_template("login.html")

# ---------------- LOGIN ROUTE ---------------- #

@app.route('/login', methods=['POST'])
def login():

    username = request.form.get('username')

    password = request.form.get('password')

    ip = request.remote_addr

    location = get_location(ip)

    attack_type = []

    risk_score = 0

    # SQL Injection Detection
    if detect_sqli(username) or detect_sqli(password):

        attack_type.append("SQL Injection")

        risk_score = 60

        print(f"ALERT: SQL Injection from {ip}")

    # Create log object
    log = {

        "ip": ip,

        "username": username,

        "password": password,

        "attack_type": attack_type,

        "risk_score": risk_score,

        "location": location,

        "timestamp": datetime.now()

    }

    print(log)

    # Save to MongoDB
    try:

        collection.insert_one(log)

        print("Data Saved To MongoDB!")

    except Exception as e:

        print("Insert Error:", e)

    # Redirect to dashboard
    return redirect("/dashboard")

# ---------------- DASHBOARD ---------------- #

@app.route('/dashboard')
def dashboard():

    try:

        logs = list(

            collection.find(

                {},

                {

                    "_id": 0,

                    "ip": 1,

                    "username": 1,

                    "attack_type": 1,

                    "risk_score": 1,

                    "location": 1

                }

            ).limit(5)

        )

    except Exception as e:

        print("Dashboard Error:", e)

        logs = []

    return render_template(

        "dashboard.html",

        logs=logs

    )

# ---------------- RUN APP ---------------- #

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5001

    )


