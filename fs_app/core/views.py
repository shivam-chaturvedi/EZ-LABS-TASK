from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse,FileResponse
from .models import AppUser, OTP,FileModel
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
import json
import jwt
import datetime
import jwt,os
from cryptography.fernet import Fernet
from .tasks import send_otp_email_task

fernet = Fernet(settings.FERNET_KEY.encode())

def decode_token(req):
    auth_header = req.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, JsonResponse({'error': 'Unauthorized'}, status=401)

    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user = AppUser.objects.get(id=decoded['id'])
        return user, None
    except (jwt.ExpiredSignatureError, jwt.DecodeError, AppUser.DoesNotExist):
        return None, JsonResponse({'error': 'Invalid or expired token'}, status=401)
    

def index(req):
    return render(req,"index.html")


@csrf_exempt
def download_file(request, encrypted_id):
    user, error = decode_token(request)
    if error:
        return error
    
    if user.role != 'client':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        decrypted_id = fernet.decrypt(encrypted_id.encode()).decode()
        file = FileModel.objects.get(id=decrypted_id)
    except:
        return JsonResponse({'error': 'Invalid or expired download link'}, status=400)
    
    filename = os.path.basename(file.file.path)

    return FileResponse(open(file.file.path, 'rb'), as_attachment=True, filename=filename)
    
@csrf_exempt
def generate_download_link(request, file_id):
    user, error = decode_token(request)
    if error: return error

    if user.role != 'client':
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    try:
        file = FileModel.objects.get(id=file_id)
    except FileModel.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)


    encrypted_id = fernet.encrypt(str(file.id).encode()).decode()
    link = f"/download-file/{encrypted_id}"

    return JsonResponse({
        "download_link": link, 
        "message": "success",  
        "filename":file.file.name.split("/")[1]
    })


@csrf_exempt
def list_uploaded_files(req):
    user, error = decode_token(req)
    if error:
        return error

    if user.role != 'client':
        return JsonResponse({'error': 'Only clients can view files'}, status=403)

    files = FileModel.objects.all().order_by('-uploaded_at')

    response = []
    for f in files:
        response.append({
            'id': f.id,
            'name': f.file.name.split('/')[-1],
        })

    return JsonResponse(response, safe=False)

@csrf_exempt
def verify_token(req):
    if req.method == 'POST':
        user, error = decode_token(req)
        if error: return error
        return JsonResponse({'valid': True, 'email': user.email, 'role': user.role})
    return JsonResponse({'error': 'Only POST allowed'}, status=405)

@csrf_exempt
def upload_file(req):
    user, error = decode_token(req)
    if error:
        return error

    if user.role != 'ops':
        return JsonResponse({'error': 'Only ops can upload files'}, status=403)

    if req.method == 'POST':
        uploaded_file = req.FILES.get('file')
        print(uploaded_file)

        if not uploaded_file:
            return JsonResponse({'error': 'No file uploaded'}, status=400)

        ext = uploaded_file.name.lower().split('.')[-1]
        if ext not in ['docx', 'pptx', 'xlsx']:
            return JsonResponse({'message': 'Only .docx, .pptx, .xlsx allowed'}, status=400)

        FileModel.objects.create(file=uploaded_file, uploaded_by=user)
        return JsonResponse({'message': 'File uploaded successfully'})

    return JsonResponse({'error': 'Only POST allowed'}, status=405)


@csrf_exempt
def register_user(req):
    if req.method == 'POST':
        data = json.loads(req.body)
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')

        if AppUser.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already registered'}, status=400)

        try:
            otp_record = OTP.objects.get(email=email)
        except OTP.DoesNotExist:
            return JsonResponse({'error': 'No OTP record found'}, status=400)

        if not otp_record.is_verified:
            return JsonResponse({'error': 'OTP not verified'}, status=400)

        user = AppUser(email=email, role=role)
        user.set_password(password)
        user.save()

        otp_record.delete()  

        return JsonResponse({'message': 'User registered successfully'}, status=201)

    elif req.method == "GET":
        return render(req, "register.html")

    return JsonResponse({"message": "Method not allowed"}, status=400)

@csrf_exempt
def req_otp(req):
    if req.method == "POST":
        data = json.loads(req.body)
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')

        if AppUser.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already registered'}, status=400)

        otp_code = OTP.generate_otp()

        OTP.objects.update_or_create(email=email, defaults={
            'otp': otp_code,
            'created_at': timezone.now(),
            'is_verified': False
        })

        try:
            # if redis is installed an drunning then use celery to send asynchronously
            send_otp_email_task.delay(
                subject=f"OTP for {email}",
                message=f"Your OTP for registration is: {otp_code}",
                recipient=email
            )
        except Exception as e:
            # otherwise synchronously
            print(f"Celery failed: {e}. Sending mail synchronously.")
            send_mail(
                subject=f"OTP for {email}",
                message=f"Your OTP for registration is: {otp_code}",
                from_email=f"OTP req {settings.EMAIL_HOST_USER}",
                recipient_list=[email],
                fail_silently=False
            )

        return JsonResponse({'message': 'OTP sent to email'})

    return JsonResponse({"error": "Only POST allowed"}, status=405)
    
@csrf_exempt
def verify_otp(req):
    if req.method == 'POST':
        data = json.loads(req.body)
        email = data.get('email')
        otp = data.get('otp')

        try:
            record = OTP.objects.get(email=email)
        except OTP.DoesNotExist:
            return JsonResponse({'error': 'No OTP req found for this email'}, status=400)

        if record.otp != otp:
            return JsonResponse({'error': 'Invalid OTP'}, status=400)

        record.is_verified = True
        record.save()

        return JsonResponse({'message': 'OTP verified successfully'})

    return JsonResponse({'error': 'Only POST allowed'}, status=405)

@csrf_exempt
def login(req):
    if req.method == 'POST':
        data = json.loads(req.body)
        email = data.get('email')
        password = data.get('password')

        try:
            user = AppUser.objects.get(email=email)
        except AppUser.DoesNotExist:
            return JsonResponse({'error': 'Invalid credentials'}, status=400)

        if not user.check_password(password):
            return JsonResponse({'error': 'Invalid credentials'}, status=400)

        payload = {
            'id': user.id,
            'email': user.email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        return JsonResponse({'token': token,"status":"success"})
    elif(req.method=="GET"):
        return render(req,"login.html")