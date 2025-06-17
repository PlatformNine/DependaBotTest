#!/bin/bash

# Wait for database to be ready
echo "Waiting for database to be ready..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "Database is ready!"

# Run migrations
echo "Running migrations..."
uv run python manage.py migrate

# Start the Django application with Gunicorn
echo "Starting Django application with Gunicorn..."
uv run gunicorn core.wsgi:application -c gunicorn.conf.py 