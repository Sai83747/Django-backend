from django.db import models

# ============================================
# ✅ UserProfile Model (Base User Data)
# ============================================

class UserProfile(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('event_manager', 'Event Manager'),
        ('staff', 'Staff'),
        ('client', 'Client'),
    )

    uid = models.CharField(max_length=128, unique=True)  # Firebase UID
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=255, blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='client')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.email} ({self.role})'

from django.db import models
from django.utils import timezone

# ============================================
# ✅ Staff Task Model
# ============================================
class StaffTask(models.Model):
    TASK_STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
    )

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    
    # FK to Event (Optional - tasks can be event-related)
    event = models.ForeignKey(
        'Event',
        on_delete=models.CASCADE,
        related_name='tasks',
        null=True,
        blank=True
    )

    # Assigned staff
    staff = models.ForeignKey(
        'Staff',
        on_delete=models.CASCADE,
        related_name='tasks'
    )

    assigned_by = models.ForeignKey(
        'EventManager',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tasks_assigned'
    )

    due_date = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=TASK_STATUS_CHOICES, default='pending')
    progress_percentage = models.PositiveIntegerField(default=0)  # Between 0-100
    rating= models.PositiveIntegerField(default=0)
    feedback = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('staff', 'event', 'title')  # prevent duplicate task titles for same staff in one event

    def __str__(self):
        return f'Task: {self.title} for Staff: {self.staff.user_profile.display_name} ({self.status})'

# ============================================
# ✅ Admin Model
# ============================================

class Admin(models.Model):
    user_profile = models.OneToOneField(
        UserProfile,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'admin'},
        related_name='admin_profile'
    )

    def __str__(self):
        return f'Admin: {self.user_profile.display_name or self.user_profile.email}'

    # Access to Event Managers
    @property
    def event_managers(self):
        return self.eventmanager_set.all()

    # Access to Staff under all Event Managers
    @property
    def all_staff(self):
        return Staff.objects.filter(event_manager__admin=self)


# ============================================
# ✅ Event Manager Model
# ============================================

class EventManager(models.Model):
    user_profile = models.OneToOneField(
        UserProfile,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'event_manager'},
        related_name='event_manager_profile'
    )

    # FK to Admin
    admin = models.ForeignKey(
        Admin,
        on_delete=models.CASCADE,
        related_name='event_managers'
    )

    def __str__(self):
        return f'Event Manager: {self.user_profile.display_name or self.user_profile.email}'

    # Access to Staff under this manager
    @property
    def staff_members(self):
        return self.staff_set.all()

    # Access to Events managed by this Event Manager
    @property
    def events(self):
        return self.managed_events.all()


# ============================================
# ✅ Event Model
# ============================================

# events/models.py
from django.db import models

class Event(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    
    # ✅ New datetime fields
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    
    location = models.CharField(max_length=255)
    image_url = models.URLField(blank=True, null=True)
    city= models.CharField(max_length=255)
    available_seats = models.PositiveIntegerField()
    price_per_seat = models.DecimalField(max_digits=10, decimal_places=2)
    manager = models.ForeignKey(
        'EventManager',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='managed_events'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # ✅ Unique together constraint
    class Meta:
        unique_together = ('title', 'start_time', 'end_time', 'location')

    def __str__(self):
        return f'Event: {self.title} ({self.start_time} - {self.end_time}) at {self.location}'

# ============================================
# ✅ Staff Model
# ============================================


class Staff(models.Model):
    user_profile = models.OneToOneField(
        UserProfile,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'staff'},
        related_name='staff_profile'
    )

    # ✅ FK to Event Manager - Make it optional
    event_manager = models.ForeignKey(
        EventManager,
        on_delete=models.SET_NULL,  # SET_NULL because we allow event_manager to be None
        null=True,                  # ✅ Allow NULLs in the database
        blank=True,                 # ✅ Allow blank in Django forms/admin
        related_name='staff_members'
    )

    # FK to Event (optional if needed)
    assigned_event = models.ForeignKey(
        Event,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='staff_assigned'
    )

    position = models.CharField(max_length=100, blank=True, null=True)
    is_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def all_tasks(self):
        return self.tasks.all()

    def __str__(self):
        return f'Staff: {self.user_profile.display_name or self.user_profile.email} - Manager: {self.event_manager.user_profile.display_name if self.event_manager else "None"}'

    @property
    def average_rating(self):
        ratings = self.ratings.all()
        if not ratings.exists():
            return 0.0
        avg = ratings.aggregate(models.Avg('rating'))['rating__avg']
        return round(avg, 2)



# ============================================
# ✅ Staff Rating Model
# ============================================

class StaffRating(models.Model):
    staff = models.ForeignKey(
        Staff,
        on_delete=models.CASCADE,
        related_name='ratings'
    )

    rated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='staff_ratings_given'
    )

    rating = models.PositiveIntegerField()
    feedback = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Rating {self.rating} for {self.staff.user_profile.display_name or self.staff.user_profile.email}'
class Booking(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='bookings')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='bookings')
    
    booking_date = models.DateTimeField(auto_now_add=True)
    number_of_tickets = models.PositiveIntegerField(default=1)
    booking_amount= models.DecimalField(max_digits=10, decimal_places=2)
    # Optional fields
    payment_status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('completed', 'Completed'),('cancelled','Cancelled')], default='pending')
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    def __str__(self):
        return f'{self.user.display_name} booked {self.event.title}'

