import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# ---------------------------
# Data Storage Setup
# ---------------------------

USERS_FILE = "users.json"
DATA_FILE = "encrypted_data.json"

def load_data(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_data(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f)

# Initialize data
users = load_data(USERS_FILE)
encrypted_data = load_data(DATA_FILE)

# ---------------------------
# Security Functions
# ---------------------------

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    return f"{salt.hex()}:{key.decode()}"

def verify_password(stored_password, input_password):
    salt_hex, stored_key = stored_password.split(":")
    salt = bytes.fromhex(salt_hex)
    input_key = generate_key(input_password, salt)
    return input_key.decode() == stored_key

# ---------------------------
# Session State Setup
# ---------------------------

if "auth" not in st.session_state:
    st.session_state.auth = {"logged_in": False, "user": None}

if "attempts" not in st.session_state:
    st.session_state.attempts = 0

# ---------------------------
# Authentication Flow
# ---------------------------

def login_section():
    st.title("🔒 Secure Data Vault")
    
    with st.expander("🚀 New User Registration"):
        new_user = st.text_input("Choose username")
        new_pass = st.text_input("Choose password", type="password", key="new_pass")
        
        if st.button("Create Account"):
            if new_user.strip() == "" or new_pass.strip() == "":
                st.error("Username/password cannot be empty!")
            elif new_user in users:
                st.error("Username already exists!")
            else:
                users[new_user] = hash_password(new_pass)
                save_data(users, USERS_FILE)
                st.success("Account created! Please login")

    st.divider()
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=100)
    
    with col2:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            if username in users and verify_password(users[username], password):
                st.session_state.auth = {"logged_in": True, "user": username}
                st.session_state.attempts = 0
                st.rerun()
            else:
                st.session_state.attempts += 1
                remaining = 3 - st.session_state.attempts
                
                if remaining > 0:
                    st.error(f"Invalid credentials! Attempts left: {remaining}")
                else:
                    st.error("🔒 Account locked! Contact admin")
                    st.stop()

# ---------------------------
# Main Application
# ---------------------------

def main_app():
    st.sidebar.title(f"Welcome {st.session_state.auth['user']}")
    choice = st.sidebar.radio("Menu", ["Store Secret", "Retrieve Secret", "Logout"])

    # Store Secret
    if choice == "Store Secret":
        st.header("🔐 Store New Secret")
        secret = st.text_area("Enter your sensitive data:", height=150)
        passkey = st.text_input("Set encryption passkey", type="password")
        
        if st.button("Encrypt & Save"):
            if secret and passkey:
                # Generate encryption parameters
                salt = os.urandom(16)
                key = generate_key(passkey, salt)
                cipher = Fernet(key)
                
                # Encrypt and store
                encrypted = cipher.encrypt(secret.encode()).decode()
                entry_id = hashlib.sha256(encrypted.encode()).hexdigest()[:8]
                
                encrypted_data[entry_id] = {
                    "user": st.session_state.auth["user"],
                    "salt": salt.hex(),
                    "encrypted": encrypted
                }
                save_data(encrypted_data, DATA_FILE)
                
                st.success(f"Secret stored successfully! Your ID: {entry_id}")
            else:
                st.warning("Both fields are required!")

    # Retrieve Secret
    elif choice == "Retrieve Secret":
        st.header("🔓 Retrieve Secret")
        entry_id = st.text_input("Enter Secret ID")
        passkey = st.text_input("Enter passkey", type="password")
        
        if st.button("Decrypt"):
            if entry_id in encrypted_data:
                entry = encrypted_data[entry_id]
                
                if entry["user"] != st.session_state.auth["user"]:
                    st.error("This secret doesn't belong to you!")
                    return
                
                try:
                    salt = bytes.fromhex(entry["salt"])
                    key = generate_key(passkey, salt)
                    cipher = Fernet(key)
                    decrypted = cipher.decrypt(entry["encrypted"].encode()).decode()
                    st.success("Decrypted Data:")
                    st.code(decrypted)
                except:
                    st.error("❌ Invalid passkey or corrupted data!")
            else:
                st.error("Invalid Secret ID!")

    # Logout
    elif choice == "Logout":
        st.session_state.auth = {"logged_in": False, "user": None}
        st.rerun()

# ---------------------------
# App Flow Control
# ---------------------------

if not st.session_state.auth["logged_in"]:
    login_section()
else:
    main_app()