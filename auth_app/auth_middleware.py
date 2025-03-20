import firebase_admin
from firebase_admin import auth as firebase_auth, credentials
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from .models import UserProfile

# Initialize Firebase Admin SDK if not already initialized



class FirebaseAuthenticationMiddleware(MiddlewareMixin):
    """
    Custom middleware to authenticate users via Firebase ID Token.
    """

    def process_request(self, request):
        # ✅ Try to extract Firebase token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        id_token = None
        if auth_header and auth_header.startswith('Bearer '):
            id_token = auth_header.split(' ')[1]

        # ✅ Optional: If you store token in cookies instead
        # id_token = request.COOKIES.get('firebase_id_token')

        if not id_token:
            # No token provided. Set request.user as AnonymousUser
            request.user = AnonymousUser()
            return

        try:
            # ✅ Verify Firebase token
            decoded_token = firebase_auth.verify_id_token(id_token)
            firebase_uid = decoded_token.get('uid')

            if not firebase_uid:
                request.user = AnonymousUser()
                return

            # ✅ Retrieve user from your Django database
            try:
                user = UserProfile.objects.get(firebase_uid=firebase_uid)
                request.user = user
            except UserProfile.DoesNotExist:
                # If user is not in your Django DB but exists in Firebase
                # Optionally, you can create a UserProfile here
                request.user = AnonymousUser()

        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Firebase ID token has expired'}, status=401)

        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

        except Exception as e:
            print(f'❌ Unexpected error in Firebase auth middleware: {e}')
            return JsonResponse({'error': 'Authentication failed'}, status=401)
