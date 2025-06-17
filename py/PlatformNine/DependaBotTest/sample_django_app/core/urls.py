from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from users.views import UserViewSet
from django.http import HttpResponse

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api-auth/', include('rest_framework.urls')),
    path('health/', lambda request: HttpResponse('OK', content_type='text/plain')),
] 