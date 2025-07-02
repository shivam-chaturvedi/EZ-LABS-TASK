from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings

@shared_task
def send_otp_email_task(subject, message, recipient):
    send_mail(
        subject=subject,
        message=message,
        from_email=f"OTP req {settings.EMAIL_HOST_USER}",
        recipient_list=[recipient],
        fail_silently=False
    )
