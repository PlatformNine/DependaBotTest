# Sample Django App

A Django application with user management features including authentication, authorization, and pagination.

## Features

- User authentication with email/password and session management
- Session storage in memcache with 24-hour expiration
- User creation with authorization
- Paginated user listing with cursor-based pagination
- PostgreSQL database
- Docker and docker-compose setup
- Production-ready with Gunicorn WSGI server

## Setup

1. Build and start the containers:
```bash
docker-compose up --build
```

2. Run migrations:
```bash
docker-compose exec web python manage.py makemigrations
docker-compose exec web python manage.py migrate
```

3. Create a superuser (optional):
```bash
docker-compose exec web python manage.py createsuperuser
```

## API Endpoints

### Login (creates session)
- POST `/api/users/login/`
- Body: `{"email": "user@example.com", "password": "password"}`
- Response includes session_id for tracking

### Logout (clears session)
- POST `/api/users/logout/`
- Requires authentication
- Clears session from memcache

### Check Session Status
- GET `/api/users/session_status/`
- Returns current authentication status and session info

### Create User (requires authentication and can_create_user permission)
- POST `/api/users/`
- Body: `{"email": "newuser@example.com", "username": "newuser", "password": "password"}`

### List Users (requires authentication)
- GET `/api/users/`
- Query parameters:
  - `cursor`: Pagination token (opaque string)
  - `limit`: Number of results per page (default: 10)

### Lookup User by Email (requires authentication)
- GET `/api/users/lookup_by_email/?email=user@example.com`

## Session Management

The application uses memcache for session storage with the following features:
- Sessions expire after 24 hours of inactivity
- Session data is stored in memcache for fast access
- Automatic cleanup of expired sessions
- Session cookies are set for browser-based access

## Development

The application uses:
- Django 5.0+
- Django REST Framework
- PostgreSQL
- Memcache for session storage
- bcrypt for password hashing
- uv for dependency management
- Gunicorn for production deployment