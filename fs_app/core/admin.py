from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(AppUser)
admin.site.register(OTP)
admin.site.register(FileModel)