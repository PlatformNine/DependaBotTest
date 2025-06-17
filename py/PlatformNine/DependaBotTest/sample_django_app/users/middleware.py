from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user
from .models import User
import logging

logger = logging.getLogger(__name__)

class MemcacheSessionMiddleware:
    """
    Middleware to handle session authentication using memcache.
    This middleware checks for the sessionid cookie and retrieves user data from memcache.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check for sessionid cookie
        session_key = request.COOKIES.get('sessionid')
        
        logger.warning(f"MemcacheSessionMiddleware: session_key = {session_key}")
        
        if session_key:
            # Try to get session data from memcache
            cached_data = cache.get(f"session_{session_key}")
            
            logger.warning(f"MemcacheSessionMiddleware: cached_data = {cached_data}")
            
            if cached_data and cached_data.get('user_id'):
                try:
                    # Get the user from the database
                    user = User.objects.get(id=cached_data['user_id'])
                    
                    logger.warning(f"MemcacheSessionMiddleware: Found user {user.email}")
                    
                    # Set session data for Django's AuthenticationMiddleware
                    if not hasattr(request, 'session'):
                        request.session = {}
                    
                    # Set the user ID in session for Django's auth system
                    request.session['_auth_user_id'] = str(user.id)
                    request.session['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
                    
                except User.DoesNotExist:
                    # User doesn't exist, clear the session
                    logger.warning(f"MemcacheSessionMiddleware: User {cached_data['user_id']} not found")
                    
                    # Debug: List all users in the database
                    all_users = User.objects.all()
                    logger.warning(f"MemcacheSessionMiddleware: Available users: {[(u.id, u.email) for u in all_users]}")
                    
                    cache.delete(f"session_{session_key}")
            else:
                # No valid session data in memcache
                logger.info("MemcacheSessionMiddleware: No valid session data in memcache")
        else:
            # No session cookie
            logger.info("MemcacheSessionMiddleware: No session cookie")

        response = self.get_response(request)
        return response 