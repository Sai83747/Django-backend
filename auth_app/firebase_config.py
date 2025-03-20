# firebase_config.py
import firebase_admin
from firebase_admin import credentials, auth, firestore

# ✅ Initialize Firebase app if not already initialized
if not firebase_admin._apps:
    cred = credentials.Certificate('firebase_credentials.json')
    firebase_app = firebase_admin.initialize_app(cred)
else:
    firebase_app = firebase_admin.get_app()

# ✅ Firebase Auth and Firestore instances
firebase_auth = auth  # For authentication functions (already there)
db = firestore.client()  # For Firestore database access


# ✅ You can now use `auth` anywhere by importing from this file.
