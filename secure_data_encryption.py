import streamlit as st
import json
import os
import hashlib
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60


if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Generate encryption key
def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

# Hash the password for storage
def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

# Encrypt text using a key
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

# Decrypt text using the key
def decrypt_text(encrypted_text, key):
    try:
        fernet_key = generate_key(key)
        cipher = Fernet(fernet_key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# Load data from storage
stored_data = load_data()



# Streamlit UI Layout
st.title("Secure Data Encryption System by Aimal Khan 🔒")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to the Data Encryption System! 🔐")
    st.markdown("""
    - Register and login to manage encrypted data.
    - Encrypt and store data securely with a passkey.
    - Retrieve and decrypt stored data using the passkey.
    - After 3 failed login attempts, you are locked for 60 seconds.
    """)

elif choice == "Register":
    st.subheader("Register New User 👤")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully! ✅")
        else:
            st.error("Both fields are required. ⚠️")

elif choice == "Login":
    st.subheader("User Login 🔑")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please wait {remaining} seconds. ⏳")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username and password:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"Welcome back, {username}! 🎉")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"Invalid credentials. Attempts left: {remaining} ⚠️")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("Too many failed attempts. Locked for 60 seconds. ⏳")
                    st.stop()
        else:
            st.error("Both fields are required. ⚠️")

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first. 🛑")
    else:
        st.subheader("Store Encrypted Data 🔒")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                entry_number = len(stored_data[st.session_state.authenticated_user]["data"]) + 1
                stored_data[st.session_state.authenticated_user]["data"].append({
                    "entry_number": entry_number,
                    "encrypted_data": encrypted
                })
                save_data(stored_data)
                st.success(f"Data encrypted and saved as Entry #{entry_number}! 🎯")
            else:
                st.error("All fields are required. ⚠️")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first. 🛑")
    else:
        st.subheader("Retrieve Data 🔍")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found. 🗃️")
        else:
            st.write("Encrypted Data Entries:")
            for entry in sorted(user_data, key=lambda x: x["entry_number"]):
                st.write(f"**Entry #{entry['entry_number']}:**")
                st.code(entry['encrypted_data'], language="text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"Decrypted: {result} 🔓")
                else:
                    st.error("Incorrect passkey or corrupted data. ⚠️")
