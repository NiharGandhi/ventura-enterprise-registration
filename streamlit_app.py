import streamlit as st
import uuid
import re
import bcrypt
import firebase_admin
from firebase_admin import credentials, db

# Initialize Firebase Admin SDK


def initialize_firebase():
    # Initialize Firebase
    CERTIFICATE = "ventura-auth-a83af-firebase-adminsdk-w852k-65559d475d.json"
    DATABASE_URL = 'https://ventura-auth-a83af-default-rtdb.asia-southeast1.firebasedatabase.app/'
    cred = credentials.Certificate(CERTIFICATE)
    firebase_admin.initialize_app(cred, {
        'databaseURL': DATABASE_URL
    })


if not firebase_admin._apps:
    initialize_firebase()

# Function to clean email for Firebase path


def clean_email(email):
    return re.sub(r'[^a-zA-Z0-9_]', '_', email)

# Streamlit App


def register_enterprise():
    st.title("Enterprise Registration")

    # Input fields
    enterprise_name = st.text_input("Enterprise Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    # Check if passwords match
    if password != confirm_password:
        st.error("Passwords do not match.")
        return

    # Register button
    if st.button("Register"):
        # Generate a unique UID for the enterprise
        unique_uid = clean_email(email)

        # Hash the password
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Define enterprise information without .read and .write rules
        enterprise_info = {
            "enterprise_name": enterprise_name,
            "email": email,
            "password": hashed_password,
            "attendance": {}
        }

        # Store enterprise information in the Firebase Realtime Database
        db.reference("/enterprises/" + unique_uid).set(enterprise_info)

        st.success(
            "Registration successful. Enterprise information stored in the database.")


# Run the Streamlit app
if __name__ == "__main__":
    register_enterprise()
