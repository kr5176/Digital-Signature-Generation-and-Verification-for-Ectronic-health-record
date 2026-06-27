import os
import functools
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

import crypto_core as cc
from db_utils import (
    get_connection, create_user, check_user_login, get_user_keys,
    get_app_public_key, upsert_application, save_signed_file, get_file_record,
)
import signature
import verification

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY is not set. Generate one with:\n"
        "  python3 -c \"import secrets; print(secrets.token_hex(32))\""
    )

APP_ID = os.environ.get("APP_ID", "app_sys_01")
APP_PRIVATE_KEY = os.environ.get("APP_PRIVATE_KEY")
if not APP_PRIVATE_KEY:
    raise RuntimeError(
        "APP_PRIVATE_KEY is not set. Run generate_app_key.py once to create the "
        "application's persistent signing key, then put the printed value in your .env."
    )
APP_PRIVATE_KEY_INT = int(APP_PRIVATE_KEY)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload cap (DoS guard)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "http://127.0.0.1:5000")
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGIN}}, supports_credentials=True)

# Make sure the app's own public key in the DB always matches the private
# key this running instance actually holds (avoids the two silently drifting).
_app_pub_hex = cc.point_to_hex(APP_PRIVATE_KEY_INT * cc.G)
upsert_application(APP_ID, _app_pub_hex)


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required."}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route('/')
def home():
    return send_from_directory('.', 'index.html')


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user and generates their real, persistent signing keypair
    SERVER-SIDE (encrypted at rest with APP_MASTER_KEY before storage)."""
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "Missing required registration parameters"}), 400
    if role not in ("admin", "patient"):
        return jsonify({"error": "Invalid role"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    user_priv, user_pub_hex = signature.generate_user_keypair()
    user_priv_enc = cc.encrypt_private_scalar(user_priv)

    success = create_user(username, password, role, user_pub_hex, user_priv_enc)
    if success:
        return jsonify({"message": "User account created successfully!"}), 201
    return jsonify({"error": "User ID already exists or system error occurred."}), 400


@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "Missing credentials"}), 400

    if check_user_login(username, password, role):
        session.clear()
        session["user_id"] = username
        session["role"] = role
        return jsonify({"message": f"Successfully logged in as {role}", "username": username, "role": role}), 200
    return jsonify({"error": "Invalid credentials or role selection verification failed."}), 401


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out."}), 200


@app.route('/get_keys', methods=['GET'])
@login_required
def fetch_keys():
    user_id = request.args.get("user_id")
    file_id = request.args.get("file_id")
    if not user_id or not file_id:
        return jsonify({"error": "Missing user_id or file_id"}), 400
    record = get_file_record(user_id, file_id)
    if not record:
        return jsonify({"error": "Keys not found"}), 404
    return jsonify(record)


@app.route('/sign', methods=['POST'])
@login_required
def sign_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    # user_id comes from the authenticated session, never from client-
    # supplied form data - prevents signing "as" an arbitrary user.
    user_id = session["user_id"]
    file_id = request.form.get('file_id')
    file_name = request.form.get('file_name', file.filename)

    if not file_id:
        return jsonify({"error": "Missing file_id"}), 400

    keys = get_user_keys(user_id)
    if not keys:
        return jsonify({"error": "No signing key on file for this account. Please re-register."}), 400

    try:
        user_priv = cc.decrypt_private_scalar(keys["user_private_key_enc"])
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    app_pub_hex = get_app_public_key(APP_ID)
    if not app_pub_hex:
        return jsonify({"error": "Application signing key not configured."}), 500

    file_content = file.read()

    result = signature.sign_file(
        user_id=user_id,
        file_id=file_id,
        file_content=file_content,
        user_priv_int=user_priv,
        app_priv_int=APP_PRIVATE_KEY_INT,
        app_pub_hex=app_pub_hex,
    )

    try:
        save_signed_file(
            file_id=file_id,
            file_name=file_name,
            file_content_hash=result["file_content_hash"],
            user_public_key=keys["user_public_key"],
            app_id=APP_ID,
            app_public_key=app_pub_hex,
            r_value=result["R"],
            r_blinded=result["R_blinded"],
            final_hash=result["final_hash"],
            uploaded_by=user_id,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except Exception as e:
        print(f"Database logging failed: {e}")
        return jsonify({"error": "Signed successfully but failed to persist record. Try again."}), 500

    return jsonify({
        "status": "Success",
        "file_id": file_id,
        "user_public_key": keys["user_public_key"],
        "app_public_key": app_pub_hex,
        "R": result["R"],
        "R_blinded": result["R_blinded"],
        "final_hash": result["final_hash"],
    })


@app.route('/verify', methods=['POST'])
@login_required
def verify_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    file_content = file.read()

    user_id = request.form.get('user_id')
    file_id = request.form.get('file_id')
    user_public_key = request.form.get('user_public_key')
    app_public_key = request.form.get('app_public_key')
    r_value = request.form.get('R')
    r_blinded = request.form.get('R_blinded')
    final_hash = request.form.get('final_hash')

    required = [user_id, file_id, user_public_key, app_public_key, r_value, r_blinded, final_hash]
    if not all(required):
        return jsonify({"error": "Missing one or more required verification parameters"}), 400

    is_valid = verification.verify_digital_signature(
        file_content, user_id, file_id, user_public_key, app_public_key,
        r_value, r_blinded, final_hash,
    )
    return jsonify({"valid": is_valid})


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, port=int(os.environ.get("PORT", 5000)))
