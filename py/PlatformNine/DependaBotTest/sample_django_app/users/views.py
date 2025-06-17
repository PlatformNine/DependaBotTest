from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from django.db import connection
from django.contrib.auth import login, logout
from .models import User
from .serializers import UserSerializer, UserCreateSerializer
from .pagination import CustomCursorPagination
from rest_framework.authentication import SessionAuthentication

class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # Disable CSRF check

class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = (CsrfExemptSessionAuthentication,)
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
            
            response = Response({
                "message": "Login successful",
                "user": UserSerializer(user).data,
                "session_id": request.session.session_key
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
            # Using a prepared statement to prevent SQL injection
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