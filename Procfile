web: sh -c "python manage.py migrate && python manage.py collectstatic --no-input && gunicorn buho.wsgi:application"
