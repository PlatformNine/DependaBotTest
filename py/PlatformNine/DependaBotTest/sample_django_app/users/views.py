from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from django.db import connection
from django.contrib.auth import login, logout
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.http import HttpResponse
from jinja2 import Environment, FileSystemLoader
import os
from .models import User
from .serializers import UserSerializer, UserCreateSerializer
from .pagination import CustomCursorPagination
from rest_framework.authentication import SessionAuthentication

class CsrfExemptLoginSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        # Exempt login endpoint from CSRF check
        if request.path.endswith('/login/') and request.method == 'POST':
            return  # Skip CSRF check for login
        return super().enforce_csrf(request)

class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = (CsrfExemptLoginSessionAuthentication,)
    queryset = User.objects.all()
    serializer_class = UserSerializer
    pagination_class = CustomCursorPagination

    def get_permissions(self):
        if self.action == 'create':
            return [permissions.IsAuthenticated()]
        if self.action == 'login':
            return [permissions.AllowAny()]
        if self.action == 'session_status':
            return [permissions.AllowAny()]  # Allow checking session status without auth
        if self.action == 'lookup_by_email_html':
            return [permissions.AllowAny()]  # Allow HTML lookup without auth
        if self.action == 'lookup_by_email_html_jinja':
            return [permissions.AllowAny()]  # Allow Jinja HTML lookup without auth
        return [permissions.IsAuthenticated()]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

    def create(self, request, *args, **kwargs):
        if not request.user.can_create_user:
            return Response(
                {"detail": "You don't have permission to create users."},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().create(request, *args, **kwargs)

    @action(detail=False, methods=['post'])
    def login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response(
                {"detail": "Please provide both email and password."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
            if not user.check_password(password):
                return Response(
                    {"detail": "Invalid credentials."},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Use Django's standard login function
            login(request, user)
            
            # Get CSRF token for subsequent requests
            csrf_token = get_token(request)
            
            response = Response({
                "message": "Login successful",
                "user": UserSerializer(user).data,
                "session_id": request.session.session_key,
                "csrf_token": csrf_token
            })
            
            return response
        except User.DoesNotExist:
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )

    @action(detail=False, methods=['post'])
    def logout(self, request):
        logout(request)
        return Response({"message": "Logout successful"})

    @action(detail=False, methods=['get'])
    def session_status(self, request):
        if request.user.is_authenticated:
            return Response({
                "authenticated": True,
                "user": UserSerializer(request.user).data,
                "session_id": request.session.session_key,
                "session_expires_in": request.session.get_expiry_age()
            })
        else:
            return Response({
                "authenticated": False,
                "message": "Not authenticated"
            })

    @action(detail=False, methods=['get'])
    def lookup_by_email(self, request):
        email = request.query_params.get('email')
        
        if not email:
            return Response(
                {"detail": "Please provide an email address."},
                status=status.HTTP_400_BAD_REQUEST
            )

        with connection.cursor() as cursor:
            # SQL injection that we expect to be found by SAST tools.

            cursor.execute(
                f"""
                SELECT id, email, username, can_create_user, is_staff, is_active
                FROM users
                WHERE email = '{email}'
                """
            )
            result = cursor.fetchone()

        if not result:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        user_data = {
            'id': result[0],
            'email': result[1],
            'username': result[2],
            'can_create_user': result[3],
            'is_staff': result[4],
            'is_active': result[5]
        }

        return Response({'user': user_data})

    @action(detail=False, methods=['get'])
    def lookup_by_email_html(self, request):
        email = request.query_params.get('email')
        
        if not email:
            return HttpResponse(
                """
                <html>
                <head><title>User Lookup Error</title></head>
                <body>
                    <h1>Error</h1>
                    <p>Please provide an email address.</p>
                    <p>Usage: /api/users/lookup_by_email_html/?email=user@example.com</p>
                </body>
                </html>
                """,
                content_type='text/html',
                status=400
            )

        try:
            user = User.objects.get(email=email)
            
            # Get all fields from the user model
            user_fields = []
            for field in User._meta.fields:
                field_name = field.name
                field_value = getattr(user, field_name)
                # Convert boolean values to readable text
                if isinstance(field_value, bool):
                    field_value = "Yes" if field_value else "No"
                # Handle None values
                elif field_value is None:
                    field_value = "N/A"
                user_fields.append((field_name, str(field_value)))
            
            # Create HTML table
            html_content = f"""
            <html>
            <head>
                <title>User Details - {user.email}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                    th {{ background-color: #f2f2f2; font-weight: bold; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .field-name {{ font-weight: bold; color: #555; }}
                    .field-value {{ color: #333; }}
                </style>
            </head>
            <body>
                <h1>User Details</h1>
                <p><strong>Email:</strong> {user.email}</p>
                <table>
                    <thead>
                        <tr>
                            <th>Field Name</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for field_name, field_value in user_fields:
                html_content += f"""
                        <tr>
                            <td class="field-name">{field_name}</td>
                            <td class="field-value">{field_value}</td>
                        </tr>
                """
            
            html_content += """
                    </tbody>
                </table>
            </body>
            </html>
            """
            
            return HttpResponse(html_content, content_type='text/html')
            
        except User.DoesNotExist:
            return HttpResponse(
                f"""
                <html>
                <head><title>User Not Found</title></head>
                <body>
                    <h1>User Not Found</h1>
                    <p>No user found with email: {email}</p>
                </body>
                </html>
                """,
                content_type='text/html',
                status=404
            )

    @action(detail=False, methods=['get'])
    def lookup_by_email_html_jinja(self, request):
        email = request.query_params.get('email')
        
        if not email:
            return HttpResponse(
                """
                <html>
                <head><title>User Lookup Error</title></head>
                <body>
                    <h1>Error</h1>
                    <p>Please provide an email address.</p>
                    <p>Usage: /api/users/lookup_by_email_html_jinja/?email=user@example.com</p>
                </body>
                </html>
                """,
                content_type='text/html',
                status=400
            )

        try:
            user = User.objects.get(email=email)
            
            # Get all fields from the user model
            user_fields = []
            for field in User._meta.fields:
                field_name = field.name
                field_value = getattr(user, field_name)
                # Convert boolean values to readable text
                if isinstance(field_value, bool):
                    field_value = "Yes" if field_value else "No"
                # Handle None values
                elif field_value is None:
                    field_value = "N/A"
                user_fields.append((field_name, str(field_value)))
            
            # Set up Jinja2 environment
            template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template('users/lookup_by_email.html')
            
            # Render template with context
            html_content = template.render(
                user=user,
                user_fields=user_fields
            )
            
            return HttpResponse(html_content, content_type='text/html')
            
        except User.DoesNotExist:
            return HttpResponse(
                f"""
                <html>
                <head><title>User Not Found</title></head>
                <body>
                    <h1>User Not Found</h1>
                    <p>No user found with email: {email}</p>
                </body>
                </html>
                """,
                content_type='text/html',
                status=404
            ) 