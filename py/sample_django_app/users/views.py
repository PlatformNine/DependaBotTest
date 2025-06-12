from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db import connection
from .models import User
from .serializers import UserSerializer, UserCreateSerializer
from .pagination import CustomCursorPagination

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    pagination_class = CustomCursorPagination

    def get_permissions(self):
        if self.action == 'create':
            return [permissions.IsAuthenticated()]
        if self.action == 'login':
            return [permissions.AllowAny()]
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
            return Response(UserSerializer(user).data)
        except User.DoesNotExist:
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )

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

        return Response(user_data) 