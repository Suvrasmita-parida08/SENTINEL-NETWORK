# app.py
import os
import datetime
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import requests

BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'sentinel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------- Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_sub = db.Column(db.String(255), unique=True, nullable=False)  # Google subject id
    email = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255))
    mac = db.Column(db.String(64), index=True)
    ip = db.Column(db.String(64))
    registered_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String(32), default='clean')  # clean, threat, blocked

class ScanReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    payload = db.Column(db.Text)  # JSON string of scan results
    threat_detected = db.Column(db.Boolean, default=False)

class Biometric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(1024), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ---------- Simple token auth (demo) ----------
# In this demo we will issue a very simple token per user (not production-ready).
TOKENS = {}

def require_token(f):
    @wraps(f)
    def inner(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error':'missing token'}), 401
        if token not in TOKENS:
            return jsonify({'error':'invalid token'}), 401
        request.user = TOKENS[token]
        return f(*args, **kwargs)
    return inner

# ---------- Google ID token verification ----------
GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"  # tokeninfo?id_token=...

def verify_google_id_token(id_token):
    """
    Verify the id_token on the server by calling Google's tokeninfo endpoint.
    Returns token info dict when valid, otherwise raise Exception.
    """
    r = requests.get(GOOGLE_TOKENINFO_URL, params={'id_token': id_token}, timeout=5)
    if r.status_code != 200:
        raise ValueError("Invalid ID token")
    info = r.json()
    # Basic checks. In production, verify aud (client id) too.
    if 'sub' not in info or 'email' not in info:
        raise ValueError("Invalid token payload")
    return info

# ---------- Routes ----------
@app.route('/auth/google', methods=['POST'])
def auth_google():
    """
    Client posts: { "id_token": "<from client Google Sign-In>" }
    Server verifies token, creates or returns user, issues a demo token.
    """
    data = request.json or {}
    id_token = data.get('id_token')
    if not id_token:
        return jsonify({'error':'id_token required'}), 400
    try:
        info = verify_google_id_token(id_token)
    except Exception as e:
        return jsonify({'error':'invalid id_token', 'detail': str(e)}), 400

    sub = info['sub']
    email = info.get('email')
    name = info.get('name', '')
    user = User.query.filter_by(google_sub=sub).first()
    if not user:
        user = User(google_sub=sub, email=email, name=name)
        db.session.add(user)
        db.session.commit()
    # issue a demo token (in real world, return signed JWT)
    token = f"demo-token-{user.id}-{int(datetime.datetime.utcnow().timestamp())}"
    TOKENS[token] = user
    return jsonify({'token': token, 'user': {'id': user.id, 'email': user.email, 'name': user.name}})

@app.route('/devices/register', methods=['POST'])
@require_token
def devices_register():
    """
    Register a device. Browser cannot automatically give MAC — client must provide it.
    Body: { name, mac (optional if not available), ip (optional) }
    """
    data = request.json or {}
    name = data.get('name') or 'Unnamed'
    mac = data.get('mac')
    ip = data.get('ip')
    owner = request.user
    d = Device(owner_id=owner.id, name=name, mac=mac, ip=ip)
    db.session.add(d)
    db.session.commit()
    return jsonify({'ok': True, 'device_id': d.id})

@app.route('/devices/<int:device_id>/report', methods=['POST'])
@require_token
def device_report(device_id):
    """
    Device (or native scanner) posts scan result JSON: { scanner_mac, nearby: [ { ssid, bssid(mac), rssi, ip, distance_estimate_m } ], reporter_info }
    """
    owner = request.user
    dev = Device.query.filter_by(id=device_id, owner_id=owner.id).first()
    if not dev:
        return jsonify({'error':'device not found or not owned'}), 404
    payload = request.get_json(force=True)
    # decide threat heuristics here (simple demo: any bssid == 'FF:FF:FF:FF:FF:00' is threat)
    nearby = payload.get('nearby', [])
    threat = False
    for n in nearby:
        bssid = n.get('bssid','').upper()
        if bssid == 'FF:FF:FF:FF:FF:00':
            threat = True
    sr = ScanReport(reporter_device_id=dev.id, payload=str(payload), threat_detected=threat)
    db.session.add(sr)
    if threat:
        dev.status = 'threat'
    db.session.commit()
    return jsonify({'ok': True, 'threat': threat})

@app.route('/devices/<int:device_id>/block', methods=['POST'])
@require_token
def device_block(device_id):
    """
    Mark a device as blocked. Native app should obey this and disconnect from wifi if it's the same device.
    """
    owner = request.user
    dev = Device.query.filter_by(id=device_id, owner_id=owner.id).first()
    if not dev:
        return jsonify({'error':'device not found'}), 404
    dev.status = 'blocked'
    db.session.commit()
    # Instruct client to disconnect (client must implement disconnect when it sees status blocked)
    return jsonify({'ok': True, 'message': 'device marked blocked'})

@app.route('/biometric/upload', methods=['POST'])
@require_token
def biometric_upload():
    """
    Accepts form-data file upload: 'file'
    Stores file on disk (demo) and records DB entry.
    """
    user = request.user
    if 'file' not in request.files:
        return jsonify({'error': 'file is required'}), 400
    f = request.files['file']
    filename = f"{user.id}_{int(datetime.datetime.utcnow().timestamp())}_{f.filename}"
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)
    b = Biometric(user_id=user.id, file_path=path)
    db.session.add(b)
    db.session.commit()
    return jsonify({'ok': True, 'biometric_id': b.id})

@app.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    # for demo only - protect in production
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/logs', methods=['GET'])
@require_token
def get_logs():
    user = request.user
    # return scan reports + devices for user
    devices = Device.query.filter_by(owner_id=user.id).all()
    reports = ScanReport.query.join(Device, ScanReport.reporter_device_id == Device.id).filter(Device.owner_id == user.id).order_by(ScanReport.timestamp.desc()).limit(200).all()
    devs = [{'id':d.id,'name':d.name,'mac':d.mac,'ip':d.ip,'status':d.status} for d in devices]
    reps = [{'id':r.id,'ts':r.timestamp.isoformat(), 'payload': r.payload, 'threat': r.threat_detected} for r in reports]
    return jsonify({'devices': devs, 'reports': reps})

# ---------- initialization ----------
if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
