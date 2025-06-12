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

# Start the Django development server
echo "Starting Django development server..."
uv run python manage.py runserver 0.0.0.0:8000 