from firebase_admin import auth
from django.core.exceptions import ValidationError

def verify_firebase_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        print(f"Firebase token verification failed: {str(e)}")
        raise ValidationError("Invalid authentication token")
