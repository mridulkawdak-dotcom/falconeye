from flask import Flask, request, render_template
from pymongo import MongoClient
from datetime import datetime
import requests
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
import certifi

# ---------------- LOAD ENV ---------------- #

load_dotenv()

app = Flask(__name__)

# ---------------- DATABASE ---------------- #

client = MongoClient(
    os.getenv("MONGO_URI"),
    tlsCAFile=certifi.where()
)

db = client.falconeye

collection = db.logs

# ---------------- DETECTION ---------------- #

def detect_sqli(text):

    patterns = [
        "'",
        "--",
        " OR ",
        "1=1",
        "DROP",
        "SELECT"
    ]

    return any(p.lower() in text.lower() for p in patterns)

# ---------------- GEO LOCATION ---------------- #

def get_location(ip):

    try:

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

            "country": data.get("country"),

            "city": data.get("city"),

            "isp": data.get("isp")
        }

    except:

        return {

            "country": "Unknown",

            "city": "Unknown",

            "isp": "Unknown"
        }

# ---------------- EMAIL ALERT ---------------- #

def send_alert(ip, attack_type):

    try:

        sender = os.getenv("EMAIL_USER")

        password = os.getenv("EMAIL_PASS")

        receiver = os.getenv("EMAIL_USER")

        message = f"""
FalconEye Security Alert

Attack Detected!

IP Address: {ip}

Attack Type: {attack_type}
"""

        msg = MIMEText(message)

        msg['Subject'] = "FalconEye Alert"

        msg['From'] = sender

        msg['To'] = receiver

        server = smtplib.SMTP("smtp.gmail.com", 587)

        server.starttls()

        server.login(sender, password)

        server.sendmail(
            sender,
            receiver,
            msg.as_string()
        )

        server.quit()

        print("Email Alert Sent!")

    except Exception as e:

        print("Email Error:", e)

# ---------------- ROUTES ---------------- #

@app.route('/')
def home():

    return render_template("index.html")

@app.route('/login_page')
def login_page():

    return render_template("login.html")

@app.route('/dashboard')
def dashboard():

    logs = list(
        collection.find().sort("timestamp", -1).limit(10)
    )

    return render_template(
        "dashboard.html",
        logs=logs
    )

# ---------------- LOGIN ---------------- #

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

        send_alert(ip, attack_type)

    log = {

        "ip": ip,

        "username": username,

        "password": password,

        "attack_type": attack_type,

        "risk_score": risk_score,

        "location": location,

        "timestamp": datetime.now()

    }

    collection.insert_one(log)

    print("Attack Saved!")

    return render_template("otp.html")

# ---------------- RUN ---------------- #

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5001
    )

