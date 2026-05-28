from flask import Flask, request, render_template
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
import certifi
import os
import requests
import smtplib
from email.mime.text import MIMEText

# ---------------- LOAD ENV ---------------- #

load_dotenv()

app = Flask(__name__)

# ---------------- DATABASE ---------------- #

client = MongoClient(

    os.getenv("MONGO_URI"),

    tlsCAFile=certifi.where(),

    serverSelectionTimeoutMS=30000,

    connectTimeoutMS=30000,

    socketTimeoutMS=30000,

    retryWrites=True

)

db = client.falconeye
collection = db.logs

# ---------------- DETECTION FUNCTIONS ---------------- #

# SQL Injection Detection
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

# Brute Force Detection
login_attempts = {}

def detect_bruteforce(ip):

    if ip not in login_attempts:
        login_attempts[ip] = 0

    login_attempts[ip] += 1

    return login_attempts[ip] > 5

# Bot Detection
def detect_bot(user_agent):

    if not user_agent:
        return False

    bots = [
        "curl",
        "python",
        "bot",
        "scanner"
    ]

    return any(b in user_agent.lower() for b in bots)

# ---------------- GEO LOCATION ---------------- #

def get_location(ip):

    # Skip localhost/private IPs
    if ip.startswith("127.") or ip.startswith("192.") or ip.startswith("10."):

        return {
            "country": "Localhost",
            "city": "Private Network",
            "isp": "Local ISP"
        }

    try:

        response = requests.get(f"http://ip-api.com/json/{ip}")

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

def send_alert(ip, attack_type, risk):

    sender = os.getenv("EMAIL_USER")
    password = os.getenv("EMAIL_PASS")

    message = f"""
FalconEye Threat Alert

IP Address: {ip}

Attack Type: {attack_type}

Risk Score: {risk}
"""

    msg = MIMEText(message)

    msg['Subject'] = "FalconEye Security Alert"
    msg['From'] = sender
    msg['To'] = sender

    try:

        server = smtplib.SMTP("smtp.gmail.com", 587)

        server.starttls()

        server.login(sender, password)

        server.sendmail(
            sender,
            sender,
            msg.as_string()
        )

        server.quit()

        print("Alert Email Sent!")

    except Exception as e:

        print("Email Error:", e)

# ---------------- ROUTES ---------------- #

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login_page')
def login_page():
    return render_template("login.html")

@app.route('/services')
def services():
    return render_template("services.html")

@app.route('/security')
def security():
    return render_template("security.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.route('/dashboard_page')
def dashboard_page():

    return render_template("dashboard_page.html")
# ---------------- LOGIN / HONEYPOT ---------------- #

@app.route('/login', methods=['POST'])
def login():

    username = request.form.get('username', '')

    password = request.form.get('password', '')

    ip = request.remote_addr

    user_agent = request.headers.get('User-Agent')

    location = get_location(ip)

    print("\n=== ATTACK CAPTURED ===")

    print("IP:", ip)

    print("Username:", username)

    print("Password:", password)

    # ---------------- DETECTION ---------------- #

    attack_type = []

    risk = 0

    # SQL Injection
    if detect_sqli(username) or detect_sqli(password):

        attack_type.append("SQL Injection")

        risk += 60

    # Brute Force
    if detect_bruteforce(ip):

        attack_type.append("Brute Force")

        risk += 30

    # Bot Activity
    if detect_bot(user_agent):

        attack_type.append("Bot Activity")

        risk += 20

    print("Attack Type:", attack_type)

    print("Risk Score:", risk)

    print("Location:", location)

    # ---------------- EMAIL ALERT ---------------- #

    try:

    # send_alert(ip, attack_type, risk)

      pass

    except Exception as e:

      print("Email Failed:", e)

    # ---------------- SAVE TO DATABASE ---------------- #

    log = {

        "ip": ip,

        "username": username,

        "password": password,

        "user_agent": user_agent,

        "attack_type": attack_type,

        "risk_score": risk,

        "location": location,

        "timestamp": datetime.now()

    }

    collection.insert_one(log)

    print("Saved to database!")

    return render_template("otp.html")

# ---------------- API ROUTES ---------------- #

# Get all logs
@app.route('/api/logs')
def get_logs():

    data = list(collection.find({}, {"_id": 0}))

    return {"logs": data}

# Get malicious IPs
@app.route('/api/malicious_ips')
def malicious_ips():

    data = collection.find({
        "risk_score": {"$gt": 50}
    })

    ips = [d["ip"] for d in data]

    return {"malicious_ips": list(set(ips))}

# ---------------- DASHBOARD ---------------- #

@app.route('/dashboard')
def dashboard():

    return render_template("dashboard.html")

# ---------------- RUN APP ---------------- #

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5001
    )