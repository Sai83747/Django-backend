from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_user, name='login_user'),
    path('logout/', views.user_logout, name='user_logout'),
      path('signup/', views.register_user, name='register_user'),
    path('user/', views.get_current_user, name='get_current_user'),
    path('logout/', views.logout_user, name='logout_user'),
    path('admini/', views.register_admin, name='register_admin'),
    path('createevent/', views.create_event, name='create_event'),
    path('cem/', views.create_event_manager, name='create_event_manager'),
    path("editevent/<int:event_id>/", views.edit_event, name="edit_event"),
    path("deleteevent/<int:event_id>/", views.delete_event, name="delete_event"),
    path('searchevent/', views.search_events, name='search_events'),

    path('book/', views.request_booking, name='request_booking'),
    path('eventdetails/<int:event_id>/', views.get_event_by_id, name='get_event_details_by_id'),
    path('booking/confirm_payment/<int:booking_id>/', views.confirm_booking_payment, name='confirm_booking_payment'),
    path('event/history/', views.view_booking_history, name='view_booking_history'),
    path('event/cancelevent/<int:booking_id>/', views.cancel_booking, name='cancel_booking'),
    path('usersbyrole/', views.get_users_by_role, name='get_users_by_role'),
    path('getalleventsclient/', views.get_all_events_client, name='get_all_events_client'),
    path('getclientbookings/<int:client_id>/', views.get_client_bookings, name='get_client_bookings'),
    path('geteventmanagerevents/<int:manager_id>/', views.get_event_manager_events, name='get_event_manager_events'),
    path('deleteuser/<int:user_id>/', views.delete_user_by_admin, name='delete_user_by_admin'),
    path('assigneventtomanager/<int:event_id>/', views.assign_event_to_manager, name='assign_event_manager'),
    path('assigntasktostaff/', views.assign_task_to_staff, name='assign_task_to_staff'),
path('hire-staff/', views.get_my_unassigned_staff, name='get_my_unassigned_staff'),
path('hire-staff/<int:staff_id>/', views.hire_staff, name='hire_staff'),
path('mystaff/', views.get_my_staff, name='get_staff'),
path('getstafftasks/<int:staff_id>/', views.get_staff_tasks, name='get_staff_tasks'),
path('eventmanagerdetails/<int:event_id>/', views.view_event_manager_details, name='view_event_manager_details'),
 path('register/admin/', views.register_admin, name='register_admin'),
    path('register/event-manager/', views.register_event_manager, name='register_event_manager'),
    path('register/staff/', views.register_staff, name='register_staff'),
    path('getmyevents/', views.get_my_events, name='get_my_events'),
    path('clients/bookings/', views.get_client_bookings, name='all_client_bookings'),

    # ✅ Fetch bookings for a specific client by ID
    path('clients/bookings/<int:client_id>/', views.get_client_bookings, name='specific_client_bookings'),

  

]
