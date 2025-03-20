from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.middleware import csrf
from utils.firebase import verify_firebase_token
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
import json
from .models import UserProfile, Admin ,Event,Staff,EventManager,Booking, StaffTask
from firebase_admin import auth as firebase_auth
from .models import UserProfile
import random
import string
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from firebase_admin import auth as firebase_auth
from .models import Event
from django.db.models import Q
from datetime import datetime
from django.db import models
import json


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime
from .models import Event
from firebase_admin import auth as firebase_auth
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from firebase_admin import auth as firebase_auth
from .models import UserProfile, Event, Booking
# views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import UserProfile
from firebase_admin import auth as firebase_auth
from django.core.mail import send_mail
from django.conf import settings

def send_welcome_email(email, display_name, role, temp_password):
    subject = f'Welcome to EMS as {role.capitalize()}!'
    
    message = f"""
Hi {display_name},

Welcome to the Event Management System (EMS)! 🎉

You have been registered as an {role}.
Please log in using the following credentials:

🔑 Email: {email}
🔐 Temporary Password: {temp_password}

👉 Please login and change your password after your first login.

Login Link: https://your-ems-app.com/login

If you have any issues, feel free to reach out to the admin team.

Best regards,  
EMS Team
    """

    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]

    try:
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        print(f"✅ Welcome email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send email to {email}: {str(e)}")

def verify_id_token(request):
    """
    Helper function to verify Firebase ID token and return decoded claims
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None, 'Authorization header missing'

    if not auth_header.startswith('Bearer '):
        return None, 'Invalid token format'

    id_token = auth_header.split(' ')[1]

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        return decoded_token, None
    except Exception as e:
        return None, f'Invalid token: {str(e)}'


@api_view(['DELETE'])
def delete_user_by_admin(request, user_id):
    # ✅ Verify token and get user info
    decoded_token, error = verify_id_token(request)
    if error:
        return Response({'error': error}, status=status.HTTP_401_UNAUTHORIZED)

    # ✅ Get role from decoded token
    user_role = decoded_token.get('role', '').lower()

    if user_role != 'admin':
        return Response({'error': 'Unauthorized. Admin access only.'}, status=status.HTTP_403_FORBIDDEN)

    try:
        user_to_delete = UserProfile.objects.get(id=user_id)
        user_to_delete.delete()
        return Response({'message': 'User deleted successfully'}, status=status.HTTP_200_OK)

    except UserProfile.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@csrf_exempt
def get_users_by_role(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Authenticate the user (Admin only)
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]

        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            role = decoded_token.get('role')

            if role != 'admin':
                return JsonResponse({'error': 'Only admins can access this endpoint'}, status=403)

        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

        # ✅ Get query params
        query_params = request.GET
        requested_role = query_params.get('role')
        requested_user_id = query_params.get('user_id')

        # ✅ Validate role (mandatory param)
        valid_roles = ['client', 'event_manager', 'staff']
        if not requested_role:
            return JsonResponse({'error': 'Missing required query param: role'}, status=400)

        if requested_role not in valid_roles:
            return JsonResponse({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}, status=400)

        # ✅ If user_id is provided, return that user in the specified role
        if requested_user_id:
            try:
                user = UserProfile.objects.get(id=requested_user_id, role=requested_role)
            except UserProfile.DoesNotExist:
                return JsonResponse({'error': f'User with ID {requested_user_id} and role {requested_role} not found'}, status=404)

            user_info = {
                'id': user.id,
                'uid': user.uid,
                'display_name': user.display_name,
                'email': user.email,
                'phone_number': user.phone_number,
                'location': user.location,
                'role': user.role
            }

            return JsonResponse({'user': user_info}, status=200)

        # ✅ If only role is provided, return all users in that role
        users_queryset = UserProfile.objects.filter(role=requested_role)

        users_data = []
        for user in users_queryset:
            users_data.append({
                'id': user.id,
                'uid': user.uid,
                'display_name': user.display_name,
                'email': user.email,
                'phone_number': user.phone_number,
                'location': user.location,
                'role': user.role
            })

        return JsonResponse({'users': users_data}, status=200)

    except Exception as e:
        print(f'❌ Error fetching users by role/user_id: {e}')
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

# @csrf_exempt
# def get_users_by_role(request):
#     if request.method != 'GET':
#         return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

#     try:
#         # ✅ Authenticate the user (Admin only)
#         auth_header = request.headers.get('Authorization')
#         if not auth_header:
#             return JsonResponse({'error': 'Authorization header missing'}, status=401)

#         parts = auth_header.split(' ')
#         if len(parts) != 2 or parts[0].lower() != 'bearer':
#             return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

#         id_token = parts[1]
#         decoded_token = firebase_auth.verify_id_token(id_token)

#         role = decoded_token.get('role')
#         if role != 'admin':
#             return JsonResponse({'error': 'Only admins can access this endpoint'}, status=403)

#         # ✅ Get role param from query params
#         query_params = request.GET
#         requested_role = query_params.get('role')

#         if not requested_role:
#             return JsonResponse({'error': 'Missing required query param: role'}, status=400)

#         if requested_role not in ['client', 'event_manager', 'staff']:
#             return JsonResponse({'error': 'Invalid role. Must be client, event_manager, or staff'}, status=400)

#         # ✅ Query users based on role
#         users_queryset = UserProfile.objects.filter(role=requested_role)

#         users_data = []
#         for user in users_queryset:
#             user_info = {
#                 'id': user.id,
#                 'uid': user.uid,
#                 'display_name': user.display_name,
#                 'email': user.email,
#                 'phone_number': user.phone_number,
#                 'location': user.location,
#                 'role': user.role
#             }

#             users_data.append(user_info)

#         return JsonResponse({'users': users_data}, status=200)

#     except firebase_auth.InvalidIdTokenError:
#         return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

#     except firebase_auth.ExpiredIdTokenError:
#         return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

#     except Exception as e:
#         print(f'❌ Error fetching users by role: {e}')
#         return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)


@csrf_exempt
def register_staff(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        # ✅ Verify Admin or Event Manager using X-Auth-Token
        auth_token = request.headers.get('X-Auth-Token')
        if not auth_token:
            return JsonResponse({'error': 'X-Auth-Token header missing'}, status=401)

        # ✅ Verify Firebase ID Token
        decoded_token = firebase_auth.verify_id_token(auth_token)
        requester_uid = decoded_token.get('uid')

        # ✅ Validate that the requester is an Admin or Event Manager
        requester_profile = UserProfile.objects.filter(uid=requester_uid).first()
        if not requester_profile or requester_profile.role not in ['admin', 'event_manager']:
            return JsonResponse({'error': 'Only admins or event managers can register staff'}, status=403)

        # ✅ Extract data from request body
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        display_name = data.get('display_name', '').strip()
        phone_number = data.get('phone_number', '').strip()
        location = data.get('location', '').strip()

        # ✅ Validate required fields
        if not all([email, display_name, phone_number, location]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        # ✅ Check if user already exists in UserProfile
        if UserProfile.objects.filter(email=email).exists():
            return JsonResponse({'error': 'User with this email already exists'}, status=400)

        # ✅ Create Firebase User with a temporary password
        password = generate_random_password()
        firebase_user = firebase_auth.create_user(
            email=email,
            password=password,
            display_name=display_name
        )
        firebase_uid = firebase_user.uid

        # ✅ Create UserProfile with role = staff
        staff_profile = UserProfile.objects.create(
            uid=firebase_uid,
            email=email,
            display_name=display_name,
            role='staff',
            phone_number=phone_number,
            location=location
        )

        # ✅ Determine if the registering user is event_manager
        event_manager = None
        manager_details = None

        if requester_profile.role == 'event_manager':
            event_manager = EventManager.objects.get(user_profile=requester_profile)
            manager_details = {
                'event_manager_id': event_manager.id,
                'display_name': requester_profile.display_name,
                'email': requester_profile.email,
                'phone_number': requester_profile.phone_number,
                'location': requester_profile.location
            }

        # ✅ Create Staff object (event_manager can be None if admin registers)
        staff_obj = Staff.objects.create(
            user_profile=staff_profile,
            event_manager=event_manager  # will be None if admin registered
        )

        # ✅ Set Firebase Custom Claims for role
        firebase_auth.set_custom_user_claims(firebase_uid, {'role': 'staff'})

        # ✅ Response
        return JsonResponse({
            'message': 'Staff registered successfully',
            'user': {
                'uid': staff_profile.uid,
                'email': staff_profile.email,
                'role': staff_profile.role,
                'display_name': staff_profile.display_name,
                'phone_number': staff_profile.phone_number,
                'location': staff_profile.location,
            },
            'event_manager': manager_details,  # None if admin registered the staff
            'temporary_password': password
        }, status=201)

    except firebase_auth.EmailAlreadyExistsError:
        return JsonResponse({'error': 'Email already exists in Firebase Auth'}, status=400)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f'❌ Exception: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from firebase_admin import auth as firebase_auth
from .models import UserProfile, Event
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from firebase_admin import auth as firebase_auth
from .models import EventManager, Event

@csrf_exempt
def get_my_events(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests are allowed'}, status=405)

    try:
        # ✅ Step 1: Extract X-Auth-Token
        id_token = request.headers.get('X-Auth-Token')

        if not id_token:
            return JsonResponse({'error': 'X-Auth-Token header missing'}, status=401)

        # ✅ Step 2: Verify the Firebase token
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
        except Exception as e:
            print(f'Firebase token verification failed: {e}')
            return JsonResponse({'error': 'Invalid or expired authentication token'}, status=401)

        # ✅ Step 3: Role check
        role = decoded_token.get('role')
        if role != 'event_manager':
            return JsonResponse({'error': 'Only event managers can access this endpoint'}, status=403)

        # ✅ Step 4: Get the authenticated event manager
        firebase_uid = decoded_token.get('uid')

        try:
            event_manager = EventManager.objects.get(user_profile__uid=firebase_uid)
        except EventManager.DoesNotExist:
            return JsonResponse({'error': 'Event Manager not found'}, status=404)

        # ✅ Step 5: Fetch all events managed by this event manager
        events = Event.objects.filter(manager=event_manager)

        # ✅ Step 6: Serialize event data
        events_data = []
        for event in events:
            events_data.append({
                'event_id': event.id,
                'title': event.title,
                'description': event.description,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'location': event.location,
                'city': event.city,
                'available_seats': event.available_seats,
                'price_per_seat': float(event.price_per_seat),
                'image_url': event.image_url,
            })

        # ✅ Step 7: Return response
        return JsonResponse({'events': events_data}, status=200)

    except Exception as e:
        print(f'❌ Exception in get_my_events: {str(e)}')
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
def get_event_manager_events(request, manager_id):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Step 1: Get the X-Auth-Token header
        id_token = request.headers.get('X-Auth-Token')
        
        if not id_token:
            return JsonResponse({'error': 'X-Auth-Token header missing'}, status=401)

        # ✅ Step 2: Verify the Firebase ID token
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
        except Exception as e:
            print(f'Firebase token verification failed: {e}')
            return JsonResponse({'error': 'Invalid or expired authentication token'}, status=401)

        # ✅ Step 3: Check the role from token claims (assuming you set 'role' in your token claims)
        role = decoded_token.get('role')
        
        if role != 'admin':
            return JsonResponse({'error': 'Only admins can access event manager events'}, status=403)

        # ✅ Step 4: Retrieve the manager by ID & role
        try:
            manager_profile = UserProfile.objects.get(id=manager_id, role='event_manager')
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'Event manager not found'}, status=404)

        # ✅ Step 5: Get events assigned to this manager
        events = Event.objects.filter(manager__id=manager_profile.id)

        events_data = []
        for event in events:
            events_data.append({
                'event_id': event.id,
                'title': event.title,
                'description': event.description,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'location': event.location,
                'available_seats': event.available_seats,
                'price_per_seat': event.price_per_seat
            })

        # ✅ Step 6: Send JSON response
        return JsonResponse({
            'manager_id': manager_profile.id,
            'manager_name': manager_profile.display_name,
            'events': events_data
        })

    except Exception as e:
        print(f'Error fetching event manager events: {e}')
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
def get_client_bookings(request, client_id=None):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Authenticate admin using X-Auth-Token
        id_token = request.headers.get('X-Auth-Token')
        if not id_token:
            return JsonResponse({'error': 'X-Auth-Token header missing'}, status=401)

        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Firebase ID token expired'}, status=401)
        except Exception as e:
            print(f'Firebase token verification failed: {e}')
            return JsonResponse({'error': 'Authentication failed'}, status=401)

        role = decoded_token.get('role')
        if role != 'admin':
            return JsonResponse({'error': 'Only admins can access client bookings'}, status=403)

        # ✅ Fetch bookings for a specific client if client_id is provided
        if client_id:
            try:
                client = UserProfile.objects.get(id=client_id, role='client')
            except UserProfile.DoesNotExist:
                return JsonResponse({'error': 'Client not found'}, status=404)

            bookings = Booking.objects.filter(user=client).select_related('event').order_by('-booking_date')

            bookings_data = [{
                'booking_id': booking.id,
                'event_title': booking.event.title,
                'number_of_tickets': booking.number_of_tickets,
                'booking_amount': str(booking.booking_amount),
                'payment_status': booking.payment_status,
                'booking_date': booking.booking_date
            } for booking in bookings]

            response = {
                'client_id': client.id,
                'client_name': client.display_name,
                'bookings': bookings_data
            }
        
        # ✅ Fetch bookings for all clients if client_id is not provided
        else:
            clients = UserProfile.objects.filter(role='client')
            all_bookings = []

            for client in clients:
                client_bookings = Booking.objects.filter(user=client).select_related('event').order_by('-booking_date')

                bookings_data = [{
                    'booking_id': booking.id,
                    'event_title': booking.event.title,
                    'number_of_tickets': booking.number_of_tickets,
                    'booking_amount': str(booking.booking_amount),
                    'payment_status': booking.payment_status,
                    'booking_date': booking.booking_date
                } for booking in client_bookings]

                all_bookings.append({
                    'client_id': client.id,
                    'client_name': client.display_name,
                    'bookings': bookings_data
                })

            response = {
                'clients_bookings': all_bookings
            }

        return JsonResponse(response, status=200)

    except Exception as e:
        print(f'❌ Error fetching client bookings: {e}')
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
def view_booking_history(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Authenticate user
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        decoded_token = firebase_auth.verify_id_token(id_token)

        uid = decoded_token.get('uid')
        if not uid:
            return JsonResponse({'error': 'Invalid token data'}, status=400)

        # ✅ Get UserProfile
        try:
            user_profile = UserProfile.objects.get(uid=uid)
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

        # ✅ Get user's bookings (all statuses)
        bookings = Booking.objects.filter(user=user_profile).select_related('event').order_by('-booking_date')

        # ✅ Build response
        booking_history = []
        for booking in bookings:
            booking_info = {
                'booking_id': booking.id,
                'event': {
                    'id': booking.event.id,
                    'title': booking.event.title,
                    'location': booking.event.location,
                    'city': booking.event.city,
                    'start_time': booking.event.start_time,
                    'end_time': booking.event.end_time,
                    'image_url': booking.event.image_url
                },
                'number_of_tickets': booking.number_of_tickets,
                'booking_amount': str(booking.booking_amount),
                'amount_paid': str(booking.amount_paid) if booking.amount_paid else "0.00",
                'payment_status': booking.payment_status,
                'booking_date': booking.booking_date
            }

            booking_history.append(booking_info)

        return JsonResponse({'bookings': booking_history}, status=200)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f'❌ Error fetching booking history: {e}')
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

@csrf_exempt
def cancel_booking(request, booking_id):
    if request.method != 'PATCH':
        return JsonResponse({'error': 'Only PATCH requests allowed'}, status=405)

    try:
        # ✅ Authenticate user
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        decoded_token = firebase_auth.verify_id_token(id_token)

        uid = decoded_token.get('uid')
        if not uid:
            return JsonResponse({'error': 'Invalid token data'}, status=400)

        # ✅ Retrieve the booking
        try:
            booking = Booking.objects.select_related('event', 'user').get(id=booking_id)
        except Booking.DoesNotExist:
            return JsonResponse({'error': 'Booking not found'}, status=404)

        # ✅ Ensure user is authorized to cancel their own booking
        if booking.user.uid != uid:
            return JsonResponse({'error': 'Unauthorized: You can only cancel your own bookings'}, status=403)

        # ✅ Ensure booking isn't already cancelled
        if booking.payment_status == 'cancelled':
            return JsonResponse({'error': 'Booking already cancelled'}, status=400)

        event = booking.event

        # ✅ Perform updates atomically
        with transaction.atomic():
            # ✅ Add seats back to the event
            event.available_seats += booking.number_of_tickets
            event.save()

            # ✅ Update booking status to 'cancelled'
            booking.payment_status = 'cancelled'
            booking.save()

        return JsonResponse({
            'message': 'Booking cancelled and seats restored successfully',
            'booking': {
                'id': booking.id,
                'payment_status': booking.payment_status,
                'number_of_tickets': booking.number_of_tickets,
                'amount_paid': str(booking.amount_paid),
                'booking_amount': str(booking.booking_amount),
                'event': {
                    'id': event.id,
                    'title': event.title,
                    'remaining_event_seats': event.available_seats
                }
            }
        }, status=200)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f'❌ Error cancelling booking: {e}')
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

@csrf_exempt
def confirm_booking_payment(request, booking_id):
    if request.method != 'PATCH':
        return JsonResponse({'error': 'Only PATCH requests allowed'}, status=405)

    try:
        # ✅ Authenticate the user
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        decoded_token = firebase_auth.verify_id_token(id_token)

        uid = decoded_token.get('uid')
        if not uid:
            return JsonResponse({'error': 'Invalid token data'}, status=400)

        # ✅ Retrieve the booking
        try:
            booking = Booking.objects.select_related('event', 'user').get(id=booking_id)
        except Booking.DoesNotExist:
            return JsonResponse({'error': 'Booking not found'}, status=404)

        # ✅ Check if the booking belongs to the user
        if booking.user.uid != uid:
            return JsonResponse({'error': 'Unauthorized: You can only confirm your own bookings'}, status=403)

        # ✅ Ensure booking isn't already completed/canceled
        if booking.payment_status == 'completed':
            return JsonResponse({'error': 'Booking payment already completed'}, status=400)
        if booking.payment_status == 'cancelled':
            return JsonResponse({'error': 'Cannot complete a canceled booking'}, status=400)

        event = booking.event

        # ✅ Check if enough seats are still available (important if payment delayed)
        if event.available_seats < booking.number_of_tickets:
            return JsonResponse({'error': 'Not enough available seats'}, status=400)

        # ✅ Perform updates atomically
        with transaction.atomic():
            # Reduce seats in Event table
            event.available_seats -= booking.number_of_tickets
            event.save()

            # Update booking details
            booking.payment_status = 'completed'
            booking.amount_paid = booking.booking_amount  # Always use booking_amount here
            booking.save()

        # ✅ Success response
        return JsonResponse({
            'message': 'Payment confirmed and seats updated successfully',
            'booking': {
                'id': booking.id,
                'event': {
                    'id': event.id,
                    'title': event.title
                },
                'number_of_tickets': booking.number_of_tickets,
                'booking_amount': str(booking.booking_amount),
                'amount_paid': str(booking.amount_paid),
                'payment_status': booking.payment_status,
                'remaining_event_seats': event.available_seats
            }
        }, status=200)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f'❌ Error confirming payment: {e}')
        return JsonResponse({'error': str(e)}, status=500)



# @csrf_exempt
# def search_events(request):
#     if request.method != 'GET':
#         return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

#     try:
#         # Verify Firebase token
#         auth_header = request.headers.get('Authorization')
#         if not auth_header:
#             return JsonResponse({'error': 'Authorization header missing'}, status=401)

#         parts = auth_header.split(' ')
#         if len(parts) != 2 or parts[0].lower() != 'bearer':
#             return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

#         id_token = parts[1]
#         decoded_token = firebase_auth.verify_id_token(id_token)

#         uid = decoded_token.get('uid')
#         role = decoded_token.get('role')

#         if not uid or not role:
#             return JsonResponse({'error': 'Invalid token data'}, status=400)

#         # Base queryset
#         events_queryset = Event.objects.all()

#         # Role-based filtering
#         if role == 'event_manager':
#             events_queryset = events_queryset.filter(manager__user_profile__uid=uid)
#         elif role == 'client':
#             pass  # No filtering, but will hide manager data later
#         elif role == 'admin':
#             pass  # Full access
#         else:
#             return JsonResponse({'error': 'Unauthorized role'}, status=403)

#         # Get query params
#         query_params = request.GET

#         title_filter = query_params.get('title')
#         location_filter = query_params.get('location')
#         date_filter = query_params.get('date')  # Format: 'YYYY-MM-DD'

#         # Search by title with wildcard support (case-insensitive)
#         if title_filter:
#             title_filter = title_filter.strip()
#             if '*' in title_filter:
#                 # Replace '*' with '%' for SQL LIKE wildcard
#                 title_filter = title_filter.replace('*', '%')
#                 events_queryset = events_queryset.filter(title__iregex=title_filter)
#             else:
#                 events_queryset = events_queryset.filter(title__icontains=title_filter)

#         # Search by location (case-insensitive)
#         if location_filter:
#             events_queryset = events_queryset.filter(location__icontains=location_filter.strip())

#         # Search by date (compare date part of start_time)
#         if date_filter:
#             try:
#                 # Parse the incoming date (YYYY-MM-DD)
#                 date_obj = datetime.strptime(date_filter.strip(), '%Y-%m-%d').date()
#                 # Filter events that start on that date
#                 events_queryset = events_queryset.filter(start_time__date=date_obj)
#             except ValueError:
#                 return JsonResponse({'error': 'Invalid date format, use YYYY-MM-DD'}, status=400)

#         # Build event response list
#         events_data = []
#         for event in events_queryset:
#             event_info = {
#                 'id': event.id,
#                 'title': event.title,
#                 'description': event.description,
#                 'start_time': event.start_time,
#                 'end_time': event.end_time,
#                 'location': event.location,
#                 'image_url': event.image_url,
#             }

#             # Show or hide event manager details
#             if role in ['admin', 'event_manager']:
#                 if event.manager:
#                     event_info['event_manager'] = {
#                         'id': event.manager.id,
#                         'display_name': event.manager.user_profile.display_name,
#                         'email': event.manager.user_profile.email,
#                         'phone_number': event.manager.user_profile.phone_number,
#                         'location': event.manager.user_profile.location,
#                     }
#                 else:
#                     event_info['event_manager'] = None
#             else:
#                 # Hide manager for clients
#                 event_info['event_manager'] = None

#             events_data.append(event_info)

#         return JsonResponse({'events': events_data}, status=200)

#     except firebase_auth.InvalidIdTokenError:
#         return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
#     except firebase_auth.ExpiredIdTokenError:
#         return JsonResponse({'error': 'Firebase ID token expired'}, status=401)
#     except Exception as e:
#         print(f"Exception in search_events: {str(e)}")
#         return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)


@csrf_exempt
def get_event_by_id(request, event_id):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Authenticate any user (all roles allowed)
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        decoded_token = firebase_auth.verify_id_token(id_token)

        uid = decoded_token.get('uid')
        role = decoded_token.get('role')

        if not uid or not role:
            return JsonResponse({'error': 'Invalid token data'}, status=400)

        # ✅ Retrieve the event by ID
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            return JsonResponse({'error': 'Event not found'}, status=404)

        # ✅ Prepare event data
        event_data = {
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'start_time': event.start_time,
            'end_time': event.end_time,
            'location': event.location,
            'city': event.city,
            'image_url': event.image_url,
            'available_seats': event.available_seats,
            'price_per_seat': event.price_per_seat,
        }

        # ✅ Show manager details for admin/event_manager, hide for client
        if role in ['admin', 'event_manager']:
            if event.manager:
                event_data['event_manager'] = {
                    'id': event.manager.id,
                    'display_name': event.manager.user_profile.display_name,
                    'email': event.manager.user_profile.email,
                    'phone_number': event.manager.user_profile.phone_number,
                    'location': event.manager.user_profile.location,
                }
            else:
                event_data['event_manager'] = None
        else:
            event_data['event_manager'] = None

        return JsonResponse({'event': event_data}, status=200)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f'❌ Error in get_event_by_id: {e}')
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

@csrf_exempt
def request_booking(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        # ✅ Authenticate the user (client role)
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        decoded_token = firebase_auth.verify_id_token(id_token)

        uid = decoded_token.get('uid')
        role = decoded_token.get('role')

        if not uid or not role or role != 'client':
            return JsonResponse({'error': 'Only clients can book events'}, status=403)

        # ✅ Get user profile
        try:
            user_profile = UserProfile.objects.get(uid=uid)
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

        # ✅ Parse the request body
        body = json.loads(request.body)
        event_id = body.get('event_id')
        number_of_tickets = int(body.get('number_of_tickets', 1))  # Default to 1 if not provided

        if not event_id or number_of_tickets < 1:
            return JsonResponse({'error': 'Invalid event_id or number_of_tickets'}, status=400)

        # ✅ Fetch event details
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            return JsonResponse({'error': 'Event not found'}, status=404)

        # ✅ Check available seats
        total_booked_tickets = Booking.objects.filter(event=event).aggregate(
            total=models.Sum('number_of_tickets')
        )['total'] or 0

        remaining_seats = event.available_seats - total_booked_tickets
        if remaining_seats < number_of_tickets:
            return JsonResponse({'error': f'Not enough seats available. Only {remaining_seats} left.'}, status=400)

        # ✅ Check for overlapping events booked by the user
        user_booked_events = Booking.objects.filter(
            user=user_profile,
            payment_status__in=['pending', 'completed']
        ).select_related('event')

        for booking in user_booked_events:
            existing_event = booking.event
            if (existing_event.start_time <= event.end_time and
                existing_event.end_time >= event.start_time):
                return JsonResponse({
                    'error': f'You have already booked another event "{existing_event.title}" '
                             f'from {existing_event.start_time} to {existing_event.end_time} that overlaps with this one.'
                }, status=400)

        # ✅ Calculate booking amount
        booking_amount = event.price_per_seat * number_of_tickets

        # ✅ Create the booking with pending status
        booking = Booking.objects.create(
            user=user_profile,
            event=event,
            number_of_tickets=number_of_tickets,
            booking_amount=booking_amount,
            payment_status='pending',
            amount_paid=None
        )

        return JsonResponse({
            'message': 'Booking request submitted successfully. Payment pending.',
            'booking': {
                'booking_id': booking.id,
                'event_title': event.title,
                'number_of_tickets': booking.number_of_tickets,
                'booking_amount': booking.booking_amount,
                'payment_status': booking.payment_status,
            }
        }, status=201)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f'❌ Error in request_booking: {e}')
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from firebase_admin import auth as firebase_auth
from .models import Event
import json

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import Event

# @csrf_exempt
# def get_all_events_client(request):
#     if request.method != 'GET':
#         return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

#     try:
#         # ✅ Get events where event managers are assigned
#         events_queryset = Event.objects.filter(manager__isnull=False)

#         # ✅ Serialize event data without manager details
#         events_data = []
#         for event in events_queryset:
#             events_data.append({
#                 'id': event.id,
#                 'title': event.title,
#                 'description': event.description,
#                 'start_time': event.start_time,
#                 'end_time': event.end_time,
#                 'location': event.location,
#                 'city': event.city,
#                 'available_seats': event.available_seats,
#                 'price_per_seat': float(event.price_per_seat),
#                 'image_url': event.image_url,
#             })

#         return JsonResponse({'events': events_data}, status=200)

#     except Exception as e:
#         print(f'❌ Error fetching events: {e}')
#         return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

@csrf_exempt
def get_all_events_client(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    role = None
    user_profile = None

    try:
        # 🔑 Verify token to see if user is authorized
        decoded_token, error = verify_id_token(request)
        if decoded_token:
            user_uid = decoded_token.get('uid')
            user_profile = UserProfile.objects.get(uid=user_uid)
            role = user_profile.role.lower()

    except Exception as e:
        print(f'⚠️ Token verification failed or user not found: {e}')
        # We are **not blocking access** for unauthenticated users.
        # role stays `None`, they get basic event info.

    try:
        # ✅ Base queryset: All events (regardless of manager assignment)
        events_queryset = Event.objects.all()

        # ✅ If event_manager, show only their events
        if role == 'event_manager':
            events_queryset = events_queryset.filter(manager__user_profile=user_profile)

        events_data = []
        for event in events_queryset:
            event_dict = {
                'id': event.id,
                'title': event.title,
                'description': event.description,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'location': event.location,
                'city': event.city,
                'available_seats': event.available_seats,
                'price_per_seat': float(event.price_per_seat),
                'image_url': event.image_url,
            }

            # ➡️ Add manager details if available and if user is admin
            if role == 'admin':
                if event.manager:
                    event_dict['manager'] = {
                        'id': event.manager.id,
                        'name': event.manager.user_profile.display_name,
                        'email': event.manager.user_profile.email,
                        'phone_number': event.manager.user_profile.phone_number,
                    }
                else:
                    event_dict['manager'] = None  # Manager not assigned

            events_data.append(event_dict)

        return JsonResponse({'events': events_data}, status=200)

    except Exception as e:
        print(f'❌ Error fetching events: {e}')
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

@csrf_exempt
def search_events(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        role = None
        uid = None

        # ✅ Optional Authentication
        auth_header = request.headers.get('Authorization')
        if auth_header:
            parts = auth_header.split(' ')
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                id_token = parts[1]
                try:
                    decoded_token = firebase_auth.verify_id_token(id_token)
                    uid = decoded_token.get('uid')
                    role = decoded_token.get('role')
                except firebase_auth.InvalidIdTokenError:
                    print('Invalid Firebase ID token')
                except firebase_auth.ExpiredIdTokenError:
                    print('Expired Firebase ID token')
            else:
                return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        # ✅ Initial queryset: Events with assigned managers only (default)
        events_queryset = Event.objects.filter(manager__isnull=False)

        # ✅ Role-based filtering (optional)
        if role == 'event_manager':
            events_queryset = events_queryset.filter(manager__user_profile__uid=uid)

        # ✅ Admin-specific manager status filtering
        if role == 'admin':
            manager_status = request.GET.get('managerstatus', '').strip().lower()
            if manager_status == 'assigned':
                events_queryset = Event.objects.filter(manager__isnull=False)
            elif manager_status == 'unassigned':
                events_queryset = Event.objects.filter(manager__isnull=True)
            # If no managerstatus param is provided, stick to default (assigned only)
        
        # ✅ GET query params for filtering
        query_params = request.GET

        title_filter = query_params.get('title')
        location_filter = query_params.get('location')
        date_filter = query_params.get('date')  # Format: YYYY-MM-DD
        city_filter = query_params.get('city')

        # ✅ Search by title (wildcard)
        if title_filter:
            title_filter = title_filter.strip()
            if '*' in title_filter:
                regex_pattern = title_filter.replace('*', '.*')
                events_queryset = events_queryset.filter(title__iregex=regex_pattern)
            else:
                events_queryset = events_queryset.filter(title__icontains=title_filter)

        # ✅ Search by location (exact match)
        if location_filter:
            location_filter = location_filter.strip()
            events_queryset = events_queryset.filter(location__iexact=location_filter)

        # ✅ Search by city (wildcard)
        if city_filter:
            city_filter = city_filter.strip()
            if '*' in city_filter:
                regex_pattern = city_filter.replace('*', '.*')
                events_queryset = events_queryset.filter(city__iregex=regex_pattern)
            else:
                events_queryset = events_queryset.filter(city__icontains=city_filter)

        # ✅ Search by date (exact match by date part)
        if date_filter:
            try:
                date_obj = datetime.strptime(date_filter.strip(), '%Y-%m-%d').date()
                events_queryset = events_queryset.filter(start_time__date=date_obj)
            except ValueError:
                return JsonResponse({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)

        # ✅ Build response
        events_data = []
        for event in events_queryset:
            event_info = {
                'id': event.id,
                'title': event.title,
                'description': event.description,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'location': event.location,
                'image_url': event.image_url,
                'city': event.city,
                'available_seats': event.available_seats,
                'price_per_seat': str(event.price_per_seat),
            }

            # ✅ Only admins and event managers get manager details
            if role in ['admin', 'event_manager']:
                if event.manager:
                    event_info['event_manager'] = {
                        'id': event.manager.id,
                        'display_name': event.manager.user_profile.display_name,
                        'email': event.manager.user_profile.email,
                        'phone_number': event.manager.user_profile.phone_number,
                        'location': event.manager.user_profile.location,
                    }
                else:
                    event_info['event_manager'] = None
            else:
                event_info['event_manager'] = None  # Hide for clients & public

            events_data.append(event_info)

        return JsonResponse({'events': events_data}, status=200)

    except Exception as e:
        print(f'❌ Exception in search_events: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from firebase_admin import auth as firebase_auth
import json

@csrf_exempt
def assign_task_to_staff(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

    try:
        # ✅ Authentication & Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header required'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            role = decoded_token.get('role')
            uid = decoded_token.get('uid')

            # ✅ Check for valid roles
            if role not in ['admin', 'event_manager']:
                return JsonResponse({'error': 'Only Admins or Event Managers can assign tasks.'}, status=403)

        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired Firebase ID token'}, status=401)

        # ✅ Parse request body
        body = json.loads(request.body.decode('utf-8'))

        staff_id = body.get('staff_id')
        event_id = body.get('event_id')
        title = body.get('title')
        description = body.get('description')
        due_date = body.get('due_date')

        if not all([staff_id, event_id, title, due_date]):
            return JsonResponse({'error': 'staff_id, event_id, title, and due_date are required'}, status=400)

        # ✅ Get Staff
        try:
            staff = Staff.objects.get(id=staff_id)
        except Staff.DoesNotExist:
            return JsonResponse({'error': 'Staff not found'}, status=404)

        # ✅ Check staff availability
        if not staff.is_available:
            return JsonResponse({'error': 'Staff member is not available for tasks'}, status=400)

        # ✅ Role-based access validation
        if role == 'event_manager':
            try:
                # Get EventManager by uid
                event_manager = EventManager.objects.get(user_profile__uid=uid)
            except EventManager.DoesNotExist:
                return JsonResponse({'error': 'Event Manager not found'}, status=404)

            # Check if the staff belongs to this event manager
            if staff.event_manager.id != event_manager.id:
                return JsonResponse({'error': 'You are not authorized to assign tasks to this staff member'}, status=403)

            assigned_by = event_manager

        elif role == 'admin':
            # Admin assigning, no need to verify manager
            assigned_by = None  # Optional, or fetch admin user if you want to track

        # ✅ Check if a duplicate task already exists (optional, unique_together enforces it)
        existing_task = StaffTask.objects.filter(
            staff=staff,
            event_id=event_id,
            title=title
        ).exists()

        if existing_task:
            return JsonResponse({'error': 'Duplicate task already assigned to this staff'}, status=400)

        # ✅ Create task
        task = StaffTask.objects.create(
            staff=staff,
            event_id=event_id,
            title=title,
            description=description,
            due_date=due_date,
            assigned_by=assigned_by
        )

        return JsonResponse({
            'message': 'Task successfully assigned.',
            'task_id': task.id
        }, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    except Exception as e:
        print(f'❌ Exception in assign_task_to_staff: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from firebase_admin import auth as firebase_auth
from .models import Staff, EventManager, Admin

# ================================
# ✅ GET: List unassigned staff
# ================================
@csrf_exempt
@csrf_exempt
def get_my_unassigned_staff(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Get X-Auth-Token from headers
        id_token = request.headers.get('X-Auth-Token')
        if not id_token:
            return JsonResponse({'error': 'X-Auth-Token header is required.'}, status=401)

        try:
            # ✅ Verify Firebase ID token
            decoded_token = firebase_auth.verify_id_token(id_token)

            # ✅ Ensure user role is Event Manager
            role = decoded_token.get('role')
            if role != 'event_manager':
                return JsonResponse({'error': 'Access denied. Only Event Managers can access this endpoint.'}, status=403)

        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token.'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired Firebase ID token.'}, status=401)
        except Exception as e:
            print(f'❌ Firebase verification error: {str(e)}')
            return JsonResponse({'error': 'Authentication failed.'}, status=401)

        # ✅ Query unassigned staff (event_manager is NULL)
        unassigned_staff_queryset = Staff.objects.filter(event_manager__isnull=True)

        # ✅ Prepare staff details
        staff_list = []
        for staff in unassigned_staff_queryset:
            user_profile = staff.user_profile
            staff_list.append({
                'staff_id': staff.id,
                'uid': user_profile.uid,
                'display_name': user_profile.display_name,
                'email': user_profile.email,
                'phone_number': user_profile.phone_number,
                'location': user_profile.location,
                'is_available': staff.is_available,
                'position': staff.position,
                'created_at': staff.created_at.isoformat(),
                'updated_at': staff.updated_at.isoformat(),
            })

        return JsonResponse({
            'unassigned_staff': staff_list,
            'count': len(staff_list)
        }, status=200)

    except Exception as e:
        print(f'❌ Exception in get_my_unassigned_staff: {str(e)}')
        return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)


# ================================
# ✅ PATCH: Hire staff by ID
# ================================
@csrf_exempt
def hire_staff(request, staff_id):
    if request.method != 'PATCH':
        return JsonResponse({'error': 'Only PATCH method is allowed.'}, status=405)

    try:
        # ✅ Authenticate event manager
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header required'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            role = decoded_token.get('role')
            if role != 'event_manager':
                return JsonResponse({'error': 'Only Event Managers can hire staff.'}, status=403)

            uid = decoded_token.get('uid')

        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired Firebase ID token'}, status=401)

        # ✅ Get Event Manager object
        try:
            event_manager = EventManager.objects.get(user_profile__uid=uid)
        except EventManager.DoesNotExist:
            return JsonResponse({'error': 'Event Manager profile not found.'}, status=404)

        # ✅ Get Staff by ID
        try:
            staff = Staff.objects.get(id=staff_id)
        except Staff.DoesNotExist:
            return JsonResponse({'error': 'Staff not found.'}, status=404)

        # ✅ Check if staff already assigned to another event manager (not Admin)
        current_manager = staff.event_manager
        is_admin_manager = Admin.objects.filter(id=current_manager.id).exists() if current_manager else False

        if current_manager and not is_admin_manager and current_manager != event_manager:
            return JsonResponse({'error': 'Staff is already assigned to another Event Manager.'}, status=400)

        # ✅ Assign staff to current Event Manager
        staff.event_manager = event_manager
        staff.save()

        # ✅ Prepare detailed response
        staff_user = staff.user_profile

        manager_role = 'admin' if is_admin_manager else 'event_manager'
        manager_name = current_manager.user_profile.display_name if current_manager else 'None'

        return JsonResponse({
            'message': f'{staff_user.display_name} has been successfully hired by {event_manager.user_profile.display_name}.',
            'staff_details': {
                'id': staff.id,
                'display_name': staff_user.display_name,
                'email': staff_user.email,
                'phone_number': staff_user.phone_number,
                'location': staff_user.location,
                'current_manager': {
                    'manager_name': manager_name,
                    'manager_role': manager_role
                }
            }
        }, status=200)

    except Exception as e:
        print(f"❌ Exception in hire_staff: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def get_staff_tasks(request, staff_id):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Authentication & Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header required'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]

        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            role = decoded_token.get('role')
            if role != 'event_manager':
                return JsonResponse({'error': 'Only event managers can view staff tasks.'}, status=403)

            firebase_uid = decoded_token.get('uid')
        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired Firebase ID token'}, status=401)

        # ✅ Get Event Manager object
        try:
            event_manager = EventManager.objects.get(user_profile__uid=firebase_uid)
        except EventManager.DoesNotExist:
            return JsonResponse({'error': 'Event Manager not found'}, status=404)

        # ✅ Get staff object and check manager ownership
        try:
            staff = Staff.objects.get(id=staff_id)
        except Staff.DoesNotExist:
            return JsonResponse({'error': 'Staff not found'}, status=404)

        if staff.event_manager != event_manager:
            return JsonResponse({'error': 'You do not have permission to view tasks for this staff.'}, status=403)

        # ✅ Get all tasks assigned to this staff
        tasks = StaffTask.objects.filter(staff=staff)

        # ✅ Serialize tasks
        task_list = []
        for task in tasks:
            task_list.append({
                'task_id': task.id,
                'title': task.title,
                'description': task.description,
                'due_date': task.due_date,
                'status': task.status,
                'event_id': task.event.id if task.event else None
            })

        return JsonResponse({'tasks': task_list}, status=200)

    except Exception as e:
        print(f'❌ Exception in get_staff_tasks: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def get_my_staff(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    try:
        # ✅ Authentication & Authorization using X-Auth-Token header
        id_token = request.headers.get('X-Auth-Token')
        if not id_token:
            return JsonResponse({'error': 'X-Auth-Token header required'}, status=401)

        # ✅ Clean the token (if frontend sends with quotes)
        id_token = id_token.strip().replace('"', '')

        try:
            # ✅ Verify Firebase ID token
            decoded_token = firebase_auth.verify_id_token(id_token)
            role = decoded_token.get('role')

            if role != 'event_manager':
                return JsonResponse({'error': 'Only event managers can view their staff.'}, status=403)

            firebase_uid = decoded_token.get('uid')

        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired Firebase ID token'}, status=401)
        except Exception as e:
            print(f'❌ Firebase verification error: {str(e)}')
            return JsonResponse({'error': 'Authentication failed.'}, status=401)

        # ✅ Get Event Manager object
        try:
            event_manager = EventManager.objects.get(user_profile__uid=firebase_uid)
        except EventManager.DoesNotExist:
            return JsonResponse({'error': 'Event Manager not found'}, status=404)

        # ✅ Get all staff under this manager
        staff_members = Staff.objects.filter(event_manager=event_manager)

        # ✅ Serialize staff data
        staff_list = []
        for staff in staff_members:
            staff_list.append({
                'staff_id': staff.id,
                'name': staff.user_profile.display_name,
                'email': staff.user_profile.email,
                'position': staff.position,
                'assigned_event_id': staff.assigned_event.id if staff.assigned_event else None,
                'is_available': staff.is_available,
                'phone_number': staff.user_profile.phone_number,
                'location': staff.user_profile.location,
                'created_at': staff.created_at,
                'updated_at': staff.updated_at,
            })

        return JsonResponse({'staff': staff_list}, status=200)

    except Exception as e:
        print(f'❌ Exception in get_my_staff: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def assign_event_to_manager(request, event_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        # ✅ Admin Authentication & Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header required'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            role = decoded_token.get('role')
            if role != 'admin':
                return JsonResponse({'error': 'Only admins can assign events to managers.'}, status=403)
        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired Firebase ID token'}, status=401)

        # ✅ Parse the request body
        body = json.loads(request.body.decode('utf-8'))
        manager_id = body.get('manager_id')

        if not manager_id:
            return JsonResponse({'error': 'Manager ID is required'}, status=400)

        # ✅ Get Event
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            return JsonResponse({'error': 'Event not found'}, status=404)

        # ✅ Check if event already assigned
        if event.manager:
            return JsonResponse({'error': 'This event is already assigned to a manager.'}, status=400)

        # ✅ Get Event Manager
        try:
            event_manager = EventManager.objects.get(id=manager_id)
        except EventManager.DoesNotExist:
            return JsonResponse({'error': 'Event Manager not found'}, status=404)

        # ✅ Check for time overlap with existing manager events
        overlapping_events = Event.objects.filter(
            manager=event_manager,
            start_time__lt=event.end_time,
            end_time__gt=event.start_time
        )

        if overlapping_events.exists():
            return JsonResponse({'error': 'Manager has a conflicting event during this time.'}, status=400)

        # ✅ Assign event to manager
        event.manager = event_manager
        event.save()

        return JsonResponse({
            'message': 'Event successfully assigned to manager.',
            'event_id': event.id,
            'manager_id': event_manager.id
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    except Exception as e:
        print(f'❌ Exception in assign_event_to_manager: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)

# @csrf_exempt
# def search_events(request):
#     if request.method != 'GET':
#         return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

#     try:
#         role = None
#         uid = None

#         # ✅ Optional Authentication
#         auth_header = request.headers.get('Authorization')
#         if auth_header:
#             parts = auth_header.split(' ')
#             if len(parts) == 2 and parts[0].lower() == 'bearer':
#                 id_token = parts[1]
#                 try:
#                     decoded_token = firebase_auth.verify_id_token(id_token)
#                     uid = decoded_token.get('uid')
#                     role = decoded_token.get('role')
#                 except firebase_auth.InvalidIdTokenError:
#                     print('Invalid Firebase ID token')
#                 except firebase_auth.ExpiredIdTokenError:
#                     print('Expired Firebase ID token')
#             else:
#                 return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

#         # ✅ Events with assigned managers only
#         events_queryset = Event.objects.filter(manager__isnull=False)

#         # ✅ Role-based filtering (optional)
#         if role == 'event_manager':
#             events_queryset = events_queryset.filter(manager__user_profile__uid=uid)

#         # ✅ GET query params
#         query_params = request.GET

#         title_filter = query_params.get('title')
#         location_filter = query_params.get('location')
#         date_filter = query_params.get('date')  # Format: YYYY-MM-DD
#         city_filter = query_params.get('city')

#         # ✅ Search by title (wildcard)
#         if title_filter:
#             title_filter = title_filter.strip()
#             if '*' in title_filter:
#                 regex_pattern = title_filter.replace('*', '.*')
#                 events_queryset = events_queryset.filter(title__iregex=regex_pattern)
#             else:
#                 events_queryset = events_queryset.filter(title__icontains=title_filter)

#         # ✅ Search by location (exact match)
#         if location_filter:
#             location_filter = location_filter.strip()
#             events_queryset = events_queryset.filter(location__iexact=location_filter)

#         # ✅ Search by city (wildcard)
#         if city_filter:
#             city_filter = city_filter.strip()
#             if '*' in city_filter:
#                 regex_pattern = city_filter.replace('*', '.*')
#                 events_queryset = events_queryset.filter(city__iregex=regex_pattern)
#             else:
#                 events_queryset = events_queryset.filter(city__icontains=city_filter)

#         # ✅ Search by date (exact match by date part)
#         if date_filter:
#             try:
#                 date_obj = datetime.strptime(date_filter.strip(), '%Y-%m-%d').date()
#                 events_queryset = events_queryset.filter(start_time__date=date_obj)
#             except ValueError:
#                 return JsonResponse({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)

#         # ✅ Build response
#         events_data = []
#         for event in events_queryset:
#             event_info = {
#                 'id': event.id,
#                 'title': event.title,
#                 'description': event.description,
#                 'start_time': event.start_time,
#                 'end_time': event.end_time,
#                 'location': event.location,
#                 'image_url': event.image_url,
#                 'city': event.city,
#                 'available_seats': event.available_seats,
#                 'price_per_seat': str(event.price_per_seat),
#             }

#             # ✅ Only admins and event managers get manager details
#             if role in ['admin', 'event_manager']:
#                 if event.manager:
#                     event_info['event_manager'] = {
#                         'id': event.manager.id,
#                         'display_name': event.manager.user_profile.display_name,
#                         'email': event.manager.user_profile.email,
#                         'phone_number': event.manager.user_profile.phone_number,
#                         'location': event.manager.user_profile.location,
#                     }
#                 else:
#                     event_info['event_manager'] = None
#             else:
#                 event_info['event_manager'] = None  # Hide for clients & public

#             events_data.append(event_info)

#         return JsonResponse({'events': events_data}, status=200)

    except Exception as e:
        print(f"❌ Exception in search_events: {str(e)}")
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)
def authenticate_user(request, allowed_roles):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return JsonResponse({'error': 'Authorization header missing'}, status=401)

    parts = auth_header.split(' ')
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

    try:
        id_token = parts[1]
        decoded_token = firebase_auth.verify_id_token(id_token)

        user_uid = decoded_token.get('uid')
        user_email = decoded_token.get('email')
        user_role = decoded_token.get('role')  # ✅ Custom claim fetched directly

        if not user_role:
            return JsonResponse({'error': 'User role not found in token'}, status=403)

        if user_role not in allowed_roles:
            return JsonResponse({'error': 'Access denied: Unauthorized role'}, status=403)

        # You can return the uid, email, and role if needed
        return {
            'uid': user_uid,
            'email': user_email,
            'role': user_role
        }

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)
    except Exception as e:
        return JsonResponse({'error': f'Authentication error: {str(e)}'}, status=500)
@csrf_exempt
@csrf_exempt
def edit_event(request, event_id):
    if request.method != 'PATCH':
        return JsonResponse({'error': 'Only PATCH requests allowed'}, status=405)

    # 🔐 Authenticate + get user info (role from token claims)
    user = authenticate_user(request, allowed_roles=['admin'])
    if isinstance(user, JsonResponse):
        return user  # Return error if auth fails

    try:
        # ✅ Fetch the event from your Event model (Django ORM)
        event = get_object_or_404(Event, id=event_id)

        # ✅ Parse the PATCH data
        data = json.loads(request.body)

        # ✅ Update the event fields dynamically
        allowed_fields = ['title', 'description', 'location', ]  # whatever fields you allow to update
        for field in allowed_fields:
            if field in data:
                setattr(event, field, data[field])

        # ✅ Save changes to the DB
        event.save()

        return JsonResponse({
            'message': 'Event updated successfully',
            'event_id': event.id,
            'updated_fields': {field: getattr(event, field) for field in allowed_fields if hasattr(event, field)}
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': f'Error updating event: {str(e)}'}, status=500)
# Function to generate random password
def generate_password(length=10):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))


@csrf_exempt
def register_event_manager(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        # ✅ Verify Admin authentication
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        decoded_token = firebase_auth.verify_id_token(id_token)
        requester_uid = decoded_token.get('uid')

        requester_profile = UserProfile.objects.filter(uid=requester_uid).first()
        if not requester_profile or requester_profile.role != 'admin':
            return JsonResponse({'error': 'Only admins can register event managers'}, status=403)

        # ✅ Extract user data from request
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        display_name = data.get('display_name', '').strip()
        phone_number = data.get('phone_number', '').strip()
        location = data.get('location', '').strip()

        if not all([email, display_name, phone_number, location]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        # ✅ Check if user already exists
        existing_user = UserProfile.objects.filter(email=email).first()
        if existing_user:
            return JsonResponse({'error': 'User already exists'}, status=400)

        # ✅ Create Firebase User
        password = generate_random_password()
        firebase_user = firebase_auth.create_user(
            email=email,
            password=password,
            display_name=display_name,
        )
        uid = firebase_user.uid

        # ✅ Create UserProfile and EventManager model
        user_profile = UserProfile.objects.create(
            uid=uid,
            email=email,
            display_name=display_name,
            role='event_manager',
            phone_number=phone_number,
            location=location
        )
        admin_obj = Admin.objects.get(user_profile=requester_profile)
        event_manager_obj = EventManager.objects.create(user_profile=user_profile, admin=admin_obj)

        # ✅ Set Firebase Claims
        firebase_auth.set_custom_user_claims(uid, {'role': 'event_manager'})

        return JsonResponse({
            'message': 'Event Manager registered successfully',
            'user': {
                'uid': user_profile.uid,
                'email': user_profile.email,
                'role': user_profile.role,
                'event_manager_id': event_manager_obj.id,
                'admin_id': admin_obj.id
            },
            'temporary_password': password
        }, status=201)

    except Exception as e:
        print(f'❌ Exception: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def register_admin(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        # ✅ Verify Admin authentication from custom header
        id_token = request.headers.get('X-Auth-Token')
        if not id_token:
            return JsonResponse({'error': 'X-Auth-Token header missing'}, status=401)

        # ✅ Verify Firebase token
        decoded_token = firebase_auth.verify_id_token(id_token)
        requester_uid = decoded_token.get('uid')

        # ✅ Check if requester is admin
        requester_profile = UserProfile.objects.filter(uid=requester_uid).first()
        if not requester_profile or requester_profile.role != 'admin':
            return JsonResponse({'error': 'Only admins can register another admin'}, status=403)

        # ✅ Extract user data from request body
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        display_name = data.get('display_name', '').strip()
        phone_number = data.get('phone_number', '').strip()
        location = data.get('location', '').strip()

        if not all([email, display_name, phone_number, location]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        # ✅ Check if user already exists
        existing_user = UserProfile.objects.filter(email=email).first()
        if existing_user:
            return JsonResponse({'error': 'User already exists'}, status=400)

        # ✅ Create Firebase user
        password = generate_random_password()  # Make sure this function exists
        firebase_user = firebase_auth.create_user(
            email=email,
            password=password,
            display_name=display_name,
        )
        uid = firebase_user.uid

        # ✅ Create UserProfile and Admin entry
        user_profile = UserProfile.objects.create(
            uid=uid,
            email=email,
            display_name=display_name,
            role='admin',
            phone_number=phone_number,
            location=location
        )
        admin_obj = Admin.objects.create(user_profile=user_profile)

        # ✅ Set Firebase custom claims
        firebase_auth.set_custom_user_claims(uid, {'role': 'admin'})

        return JsonResponse({
            'message': 'Admin registered successfully',
            'user': {
                'uid': user_profile.uid,
                'email': user_profile.email,
                'role': user_profile.role,
                'admin_id': admin_obj.id
            },
            'temporary_password': password
        }, status=201)

    except Exception as e:
        print(f'❌ Exception: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)



@csrf_exempt
@csrf_exempt
def create_event_manager(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        # ✅ Verify Firebase ID token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]

        # ✅ Decode the token and fetch admin UID + email
        decoded_token = firebase_auth.verify_id_token(id_token)
        admin_uid = decoded_token.get('uid')
        admin_email = decoded_token.get('email')

        if not admin_uid or not admin_email:
            return JsonResponse({'error': 'Invalid token data'}, status=400)

        # ✅ Fetch the admin user profile
        try:
            admin_profile = UserProfile.objects.get(uid=admin_uid, role='admin')
            admin = Admin.objects.get(user_profile=admin_profile)
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'Admin user not found'}, status=404)
        except Admin.DoesNotExist:
            return JsonResponse({'error': 'Admin profile not found'}, status=404)

        # ✅ Parse request body (event manager data)
        data = json.loads(request.body)
        display_name = data.get('display_name', '').strip()
        email = data.get('email', '').strip()
        phone_number = data.get('phone_number', '').strip()
        location = data.get('location', '').strip()

        # ✅ Backend validation
        if not display_name or not email or not phone_number or not location:
            return JsonResponse({'error': 'All fields are required (display_name, email, phone_number, location)'}, status=400)

        # ✅ Check if a user profile already exists for this email
        if UserProfile.objects.filter(email=email).exists():
            return JsonResponse({'error': 'A user with this email already exists'}, status=400)

        # ✅ Create a Firebase user for the event manager (if needed)
        try:
            firebase_user = firebase_auth.get_user_by_email(email)
        except firebase_auth.UserNotFoundError:
            random_password = generate_password(10)

        firebase_user = firebase_auth.create_user(
        email=email,
        password=random_password
      )

        firebase_uid = firebase_user.uid

        # ✅ Create a user profile for the event manager
        event_manager_profile = UserProfile.objects.create(
            uid=firebase_uid,
            email=email,
            display_name=display_name,
            role='event_manager',
            phone_number=phone_number,
            location=location
        )


        # ✅ Create EventManager entry linked to this admin
        event_manager = EventManager.objects.create(
            user_profile=event_manager_profile,
            admin=admin
        )

        # ✅ Set custom claims for the new event manager
        firebase_auth.set_custom_user_claims(firebase_uid, {'role': 'event_manager'})

        return JsonResponse({
    'message': 'Event manager registered successfully',
    'event_manager': {
        'uid': event_manager_profile.uid,
        'email': event_manager_profile.email,
        'role': event_manager_profile.role,
        'admin': admin_profile.display_name,
        'generated_password': random_password  # Optional: admin gets the password
    }
}, status=201)


    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)



# 
import random
import string
from firebase_admin import auth as firebase_auth

def generate_random_password(length=12):
    """Generates a secure random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


@csrf_exempt
def register_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        print("➡️ Incoming request body:", request.body)
        print("➡️ Incoming headers:", request.headers)

        # ✅ Parse JSON
        data = json.loads(request.body)

        # ✅ Validate Firebase Auth header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header is required'}, status=400)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]

        # ✅ Extract fields from request body
        display_name = data.get('display_name', '').strip()
        phone_number = data.get('phone_number', '').strip()
        location = data.get('location', '').strip()

        # ✅ Minimal backend validation
        if not display_name:
            return JsonResponse({'error': 'Display name is required'}, status=400)

        if not phone_number:
            return JsonResponse({'error': 'Phone number is required'}, status=400)

        if not location:
            return JsonResponse({'error': 'Location is required'}, status=400)

        # ✅ Verify Firebase token
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token.get('uid')
        email = decoded_token.get('email')

        if not uid or not email:
            return JsonResponse({'error': 'Invalid token data'}, status=400)

        # ✅ Prevent duplicate registration
        if UserProfile.objects.filter(uid=uid).exists():
            return JsonResponse({'error': 'User already registered'}, status=400)

        # ✅ Create user in DB
        user_profile = UserProfile.objects.create(
            uid=uid,
            email=email,
            display_name=display_name,
            role='admin',  # Default is 'client', could omit this if your model default works fine
            phone_number=phone_number,
            location=location
        )

        print(f"✅ User registered! UID: {user_profile.uid}, Email: {user_profile.email}")
        role = 'client'  # Or 'admin' / 'organizer' depending on logic
        firebase_auth.set_custom_user_claims(uid, {'role': role})
        print(f"✅ Custom claim 'role: {role}' assigned to UID: {uid}")
        return JsonResponse({
            'message': 'User registered successfully',
            'user': {
                'uid': user_profile.uid,
                'email': user_profile.email,
                'role': user_profile.role
            }
        }, status=201)


    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)



from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from firebase_admin import auth as firebase_auth
import json
from .models import Event, UserProfile, EventManager

# views.py or wherever your create_event logic is

# @csrf_exempt
# def create_event(request):
#     if request.method != 'POST':
#         return JsonResponse({'error': 'Method not allowed'}, status=405)

#     auth_header = request.headers.get('Authorization')
#     if not auth_header:
#         return JsonResponse({'error': 'Authorization header missing'}, status=401)

#     try:
#         id_token = auth_header.split(' ')[1]
#         decoded_token = firebase_auth.verify_id_token(id_token)
#         uid = decoded_token['uid']

#         try:
#             user = UserProfile.objects.get(uid=uid)
#         except UserProfile.DoesNotExist:
#             return JsonResponse({'error': 'User not found'}, status=404)

#         if user.role != 'admin':
#             return JsonResponse({'error': 'Permission denied: Admins only'}, status=403)

#         # ✅ Parse request body
#         body = json.loads(request.body)
#         title = body.get('title')
#         description = body.get('description')
#         start_time = body.get('start_time')  # Expect ISO 8601 string
#         end_time = body.get('end_time')      # Expect ISO 8601 string
#         location = body.get('location')
#         image_url = body.get('image_url')
#         manager_id = body.get('manager_id')

#         # ✅ Basic validation
#         if not title or not start_time or not end_time or not location:
#             return JsonResponse({'error': 'Missing required fields (title, start_time, end_time, location)'}, status=400)

#         # ✅ Check for duplicates (respect unique_together constraint)
#         duplicate_event = Event.objects.filter(
#             title=title,
#             start_time=start_time,
#             end_time=end_time,
#             location=location
#         ).first()

#         if duplicate_event:
#             return JsonResponse({
#                 'error': 'An event with the same title, start_time, end_time, and location already exists',
#                 'event_id': duplicate_event.id
#             }, status=400)

#         # ✅ Assign manager if provided
#         manager = None
#         if manager_id:
#             try:
#                 manager = EventManager.objects.get(id=manager_id)
#             except EventManager.DoesNotExist:
#                 return JsonResponse({'error': 'Event manager not found'}, status=404)

#         # ✅ Create event
#         event = Event.objects.create(
#             title=title,
#             description=description,
#             start_time=start_time,
#             end_time=end_time,
#             location=location,
#             image_url=image_url,
#             manager=manager
#         )

#         return JsonResponse({
#             'message': 'Event created successfully',
#             'event': {
#                 'id': event.id,
#                 'title': event.title,
#                 'description': event.description,
#                 'start_time': event.start_time,
#                 'end_time': event.end_time,
#                 'location': event.location,
#                 'image_url': event.image_url,
#                 'manager': manager.user_profile.display_name if manager else 'Unassigned'
#             }
#         }, status=201)

#     except Exception as e:
#         print(f'❌ Error creating event: {e}')
#         return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)
@csrf_exempt
def view_event_manager_details(request, event_id):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests are allowed'}, status=405)

    try:
        # ✅ Authenticate using Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            uid = decoded_token.get('uid')
            role = decoded_token.get('role')
        except firebase_auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)
        except firebase_auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired Firebase ID token'}, status=401)

        # ✅ Only admins are allowed
        if role != 'admin':
            return JsonResponse({'error': 'Only admin users can access this endpoint'}, status=403)

        # ✅ Fetch event by event_id
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            return JsonResponse({'error': 'Event not found'}, status=404)

        # ✅ Check if manager is assigned
        manager = event.manager
        if not manager:
            return JsonResponse({'message': 'No event manager is assigned to this event yet.'}, status=200)

        # ✅ Manager details from related user_profile
        manager_profile = manager.user_profile
        manager_data = {
            'event_manager_id': manager.id,
            'display_name': manager_profile.display_name,
            'email': manager_profile.email,
            'phone_number': manager_profile.phone_number,
            'location': manager_profile.location,
            'assigned_admin': manager.admin.user_profile.display_name if manager.admin else None,
        }

        # ✅ Successful response
        return JsonResponse({'event_id': event.id, 'event_title': event.title, 'event_manager': manager_data}, status=200)

    except Exception as e:
        print(f'❌ Exception in view_event_manager_details: {str(e)}')
        return JsonResponse({'error': 'An unexpected error occurred'}, status=500)
@csrf_exempt
def create_event(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return JsonResponse({'error': 'Authorization header missing'}, status=401)

    try:
        id_token = auth_header.split(' ')[1]
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token['uid']

        try:
            user = UserProfile.objects.get(uid=uid)
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

        # ✅ Only admins can create events
        if user.role != 'admin':
            return JsonResponse({'error': 'Permission denied: Admins only'}, status=403)

        # ✅ Parse request body
        body = json.loads(request.body)

        # Required fields
        title = body.get('title')
        description = body.get('description')
        start_time = body.get('start_time')  # Expect ISO 8601 string
        end_time = body.get('end_time')      # Expect ISO 8601 string
        location = body.get('location')
        image_url = body.get('image_url')
        manager_id = body.get('manager_id')

        # ✅ New fields (Optional/Required based on your needs)
        city = body.get('city')
        available_seats = body.get('available_seats')
        price_per_seat = body.get('price_per_seat')

        # ✅ Basic validation
        if not title or not start_time or not end_time or not location:
            return JsonResponse({'error': 'Missing required fields (title, start_time, end_time, location)'}, status=400)

        # ✅ Validation for new fields (Optional strictness)
        if city is None:
            return JsonResponse({'error': 'City is required'}, status=400)

        if available_seats is None or not isinstance(available_seats, int) or available_seats < 0:
            return JsonResponse({'error': 'available_seats must be a positive integer'}, status=400)

        if price_per_seat is None:
            return JsonResponse({'error': 'price_per_seat is required'}, status=400)

        try:
            # Convert string/float to Decimal (optional if client sends decimal)
            price_per_seat = float(price_per_seat)
        except ValueError:
            return JsonResponse({'error': 'price_per_seat must be a valid number'}, status=400)

        # ✅ Check for duplicates (respect unique_together constraint)
        duplicate_event = Event.objects.filter(
            title=title,
            start_time=start_time,
            end_time=end_time,
            location=location
        ).first()

        if duplicate_event:
            return JsonResponse({
                'error': 'An event with the same title, start_time, end_time, and location already exists',
                'event_id': duplicate_event.id
            }, status=400)

        # ✅ Assign manager if provided
        manager = None
        if manager_id:
            try:
                manager = EventManager.objects.get(id=manager_id)
            except EventManager.DoesNotExist:
                return JsonResponse({'error': 'Event manager not found'}, status=404)

        # ✅ Create event with new fields
        event = Event.objects.create(
            title=title,
            description=description,
            start_time=start_time,
            end_time=end_time,
            location=location,
            image_url=image_url,
            city=city,
            available_seats=available_seats,
            price_per_seat=price_per_seat,
            manager=manager
        )

        return JsonResponse({
            'message': 'Event created successfully',
            'event': {
                'id': event.id,
                'title': event.title,
                'description': event.description,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'location': event.location,
                'image_url': event.image_url,
                'city': event.city,
                'available_seats': event.available_seats,
                'price_per_seat': str(event.price_per_seat),  # Return as string for JSON
                'manager': manager.user_profile.display_name if manager else 'Unassigned'
            }
        }, status=201)

    except Exception as e:
        print(f'❌ Error creating event: {e}')
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)


@api_view(['POST'])
def firebase_login(request):
    id_token = request.data.get('idToken')

    if not id_token:
        return Response({'error': 'ID token is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        decoded_token = verify_firebase_token(id_token)
    except ValidationError as e:
        return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)

    email = decoded_token.get('email')
    uid = decoded_token.get('uid')

    if not email:
        return Response({'error': 'Email not found in token.'}, status=status.HTTP_400_BAD_REQUEST)

    # Create or get the Django user
    user, created = User.objects.get_or_create(username=email, defaults={'email': email})

    if created:
        user.set_unusable_password()
        user.save()

    # Log in and create a Django session
    login(request, user)

    # Create CSRF token for frontend to use (optional but recommended)
    csrf_token = csrf.get_token(request)

    return Response({
        'message': 'Login successful',
        'user': user.username,
        'csrfToken': csrf_token,
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
def user_logout(request):
    logout(request)
    response = Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
    response.delete_cookie('sessionid')
    return response
@csrf_exempt
def delete_event(request, event_id):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'Only DELETE requests allowed'}, status=405)

    try:
        # ✅ Get and verify the Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=401)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]

        # ✅ Verify Firebase ID token
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token.get('uid')
        role = decoded_token.get('role')  # <-- ROLE FROM CUSTOM CLAIMS

        if not uid:
            return JsonResponse({'error': 'Invalid token data'}, status=400)

        # ✅ Check if user is an admin (from the token)
        if role != 'admin':
            return JsonResponse({'error': 'Permission denied: Admins only'}, status=403)

        # ✅ Find the event to delete
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            return JsonResponse({'error': 'Event not found'}, status=404)

        # ✅ Delete the event
        event.delete()

        return JsonResponse({'message': 'Event deleted successfully'}, status=200)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f"❌ Exception in delete_event: {str(e)}")
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)
@csrf_exempt
def login_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        # ✅ Get Firebase ID Token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Authorization header is required'}, status=400)

        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return JsonResponse({'error': 'Invalid Authorization header format'}, status=400)

        id_token = parts[1]
        print(f"🔐 ID Token: {id_token}")
        # ✅ Verify the Firebase ID token
        decoded_token = firebase_auth.verify_id_token(id_token)

        uid = decoded_token.get('uid')
        email = decoded_token.get('email')

        if not uid or not email:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        # ✅ Get role from token claims or fetch custom claims from user record
        role = decoded_token.get('role')

        if not role:
            # If the role claim is not present, fallback to custom claims from Firebase user
            custom_claims = firebase_auth.get_user(uid).custom_claims
            role = custom_claims.get('role') if custom_claims else 'client'
        print(f"🔐 Fetched custom claim 'role: {role}' for UID: {uid}")
        # ✅ (Optional) Create session - Django session example
        request.session['uid'] = uid
        request.session['email'] = email
        request.session['role'] = role
        request.session['id_token'] = id_token
        request.session.set_expiry(60 * 60 * 24)  # Session expires in 1 day (adjust as needed)

        # ✅ Return success with user info
        return JsonResponse({
            'message': 'Login successful',
            'user': {
                'uid': uid,
                'email': email,
                'role': role,
            }
        }, status=200)

    except firebase_auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid Firebase ID token'}, status=401)

    except firebase_auth.ExpiredIdTokenError:
        return JsonResponse({'error': 'Firebase ID token expired'}, status=401)

    except Exception as e:
        print(f"❌ Exception in login: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
@csrf_exempt
def get_current_user(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET requests allowed'}, status=405)

    uid = request.session.get('uid')
    email = request.session.get('email')
    role = request.session.get('role')
    id_token = request.session.get('id_token')

    if not uid or not email:
        return JsonResponse({'error': 'User not authenticated'}, status=401)

    print(f"✅ Session valid for user UID: {uid}")

    return JsonResponse({
        'user': {
            'uid': uid,
            'email': email,
            'role': role,
            'id_token': id_token
        }
    }, status=200)
@csrf_exempt
def logout_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

    try:
        request.session.flush()  # Deletes session data
        return JsonResponse({'message': 'Logged out successfully'}, status=200)
    except Exception as e:
        print(f"❌ Exception in logout_user: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)