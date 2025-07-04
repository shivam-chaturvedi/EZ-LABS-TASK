# EZ-LABS-TASK

## Run the Application (Development)

```bash
git clone https://github.com/shivam-chaturvedi/EZ-LABS-TASK.git
cd EZ-LABS-TASK

python -m venv .venv
source .venv/bin/activate 

pip install -r requirements.txt

export SECRET_KEY='secret-key'
export EMAIL_HOST_USER='email@example.com'
export EMAIL_HOST_PASSWORD='app-password'
export DATABASE_URL='database-url'
export REDIS_URL='redis://localhost:6379/0'

cd fs_app
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
````

In a separate terminal:
In same folder fs_app
```bash
celery -A fs_app worker --loglevel=info
```

## Deployment Steps

Set `DEBUG = False` in `settings.py`

Set environment variables for secret keys, email credentials, and redis

Update Redis settings with remote credentials

Update the file model to use a URLField

Use Firebase, AWS S3, or other storage for file uploads and store their URLs

Set up WhiteNoise for serving static files

Use a production-ready database like AWS RDS and update `DATABASES` settings

Set `ALLOWED_HOSTS` to your domain or server IP

Use Gunicorn as the WSGI server

Use Nginx as a reverse proxy and for SSL configuration

Use HTTPS by enabling SSL with Let's Encrypt

Update these settings in `settings.py`

```python
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

## Production Commands

```bash
python manage.py collectstatic --noinput
gunicorn fs_app.wsgi:application --bind 0.0.0.0:8000
celery -A fs_app worker --loglevel=info
```

```
```
