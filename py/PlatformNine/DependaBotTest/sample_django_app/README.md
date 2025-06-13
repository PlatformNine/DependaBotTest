# Sample Django App

A Django application with user management features including authentication, authorization, and pagination.

## Features

- User authentication with email/password
- User creation with authorization
- Paginated user listing with cursor-based pagination
- PostgreSQL database
- Docker and docker-compose setup

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

### Login
- POST `/api/users/login/`
- Body: `{"email": "user@example.com", "password": "password"}`

### Create User (requires authentication and can_create_user permission)
- POST `/api/users/`
- Body: `{"email": "newuser@example.com", "username": "newuser", "password": "password"}`

### List Users (requires authentication)
- GET `/api/users/`
- Query parameters:
  - `cursor`: Pagination token (opaque string)
  - `limit`: Number of results per page (default: 10)

## Development

The application uses:
- Django 5.0+
- Django REST Framework
- PostgreSQL
- bcrypt for password hashing
- uv for dependency management 