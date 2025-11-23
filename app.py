import base64
import re
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# 簡易DB
users_db = {
    "TaroYamada": {
        "user_id": "TaroYamada",
        "password": "PaSSwd4TY",
        "nickname": "たろー",
        "comment": "僕は元気です"
    }
}

REGEX_USER_ID = re.compile(r'^[a-zA-Z0-9]+$')
REGEX_PASSWORD = re.compile(r'^[\x21-\x7E]+$')

def has_control_codes(text):
    if text is None: return False
    return bool(re.search(r'[\x00-\x1f\x7f]', text))

def authenticate_user(req):
    auth_header = req.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '): return None
    try:
        encoded = auth_header.split(' ')[1]
        decoded = base64.b64decode(encoded).decode('utf-8')
        if ':' not in decoded: return None
        uid, pwd = decoded.split(':', 1)
        if uid in users_db and users_db[uid]['password'] == pwd: return uid
    except: return None
    return None

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    password = data.get('password')

    if not user_id or not password:
        return jsonify({"message": "Account creation failed", "cause": "Required user_id and password"}), 400
    if not (6 <= len(user_id) <= 20) or not (8 <= len(password) <= 20):
        return jsonify({"message": "Account creation failed", "cause": "Input length is incorrect"}), 400
    if not REGEX_USER_ID.match(user_id) or not REGEX_PASSWORD.match(password):
        return jsonify({"message": "Account creation failed", "cause": "Incorrect character pattern"}), 400
    if user_id in users_db:
        return jsonify({"message": "Account creation failed", "cause": "Already same user_id is used"}), 400

    users_db[user_id] = {"user_id": user_id, "password": password, "nickname": user_id, "comment": ""}
    return jsonify({"message": "Account successfully created", "user": {"user_id": user_id, "nickname": user_id}}), 200

@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    if not authenticate_user(request): return jsonify({"message": "Authentication Failed"}), 401
    if user_id not in users_db: return jsonify({"message": "No user found"}), 404
    u = users_db[user_id]
    return jsonify({"message": "User details by user_id", "user": {"user_id": u["user_id"], "nickname": u["nickname"], "comment": u["comment"]}}), 200

@app.route('/users/<user_id>', methods=['PATCH'])
def update_user(user_id):
    auth_user = authenticate_user(request)
    if not auth_user: return jsonify({"message": "Authentication Failed"}), 401
    if user_id not in users_db: return jsonify({"message": "No user found"}), 404
    if auth_user != user_id: return jsonify({"message": "No permission for update"}), 403

    data = request.get_json(silent=True) or {}
    if 'user_id' in data or 'password' in data:
        return jsonify({"message": "User updation failed", "cause": "Not updatable user_id and password"}), 400
    if 'nickname' not in data and 'comment' not in data:
        return jsonify({"message": "User updation failed", "cause": "Required nickname or comment"}), 400

    new_nick, new_comm = data.get('nickname'), data.get('comment')
    if new_nick is not None and (len(new_nick) > 30 or has_control_codes(new_nick)):
        return jsonify({"message": "User updation failed", "cause": "String length limit exceeded or invalid pattern"}), 400
    if new_comm is not None and (len(new_comm) > 100 or has_control_codes(new_comm)):
        return jsonify({"message": "User updation failed", "cause": "String length limit exceeded or invalid pattern"}), 400

    u = users_db[user_id]
    if 'nickname' in data: u['nickname'] = user_id if new_nick == "" else new_nick
    if 'comment' in data: u['comment'] = "" if new_comm == "" else new_comm
    users_db[user_id] = u
    return jsonify({"message": "User successfully updated", "user": {"user_id": u['user_id'], "nickname": u['nickname'], "comment": u['comment']}}), 200

@app.route('/close', methods=['POST'])
def close_account():
    auth_user = authenticate_user(request)
    if not auth_user: return jsonify({"message": "Authentication Failed"}), 401
    if auth_user in users_db: del users_db[auth_user]
    return jsonify({"message": "Account and user successfully removed"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)