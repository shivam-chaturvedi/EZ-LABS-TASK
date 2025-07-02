import random
from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

class AppUser(models.Model):
    ROLE_CHOICES = (
        ('ops', 'Operations'),
        ('client', 'Client'),
    )

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(default=timezone.now)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.email

class OTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now)    
    is_verified = models.BooleanField(default=False)

    @classmethod
    def generate_otp(self):
        return str(random.randint(100000, 999999))

class FileModel(models.Model):
    file = models.FileField(upload_to='uploads/')
    uploaded_by = models.ForeignKey(AppUser, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.file.name