from django.urls import path
from .views import *

urlpatterns = [
    path('register', register_user),
    path('request_otp', req_otp),
    path('verify_otp', verify_otp),
    path("login",login),
    path("verify-token",verify_token),
    path("",index),
    path("upload",upload_file),
    path("files",list_uploaded_files),
    path("generate-download/<int:file_id>",generate_download_link),
    path('download-file/<str:encrypted_id>', download_file),
]
