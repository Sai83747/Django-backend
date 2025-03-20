from django.contrib import admin
from .models import UserProfile, Event, Staff,StaffRating,EventManager,Admin,Booking,StaffTask
admin.site.register(UserProfile)
admin.site.register(Event)
admin.site.register(Staff)
admin.site.register(StaffRating)
admin.site.register(EventManager)
admin.site.register(Admin)
admin.site.register(Booking)
admin.site.register(StaffTask)

# Register your models here.
