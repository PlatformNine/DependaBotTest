"""
Pytest configuration for Django tests.
"""

import os
import django
from django.conf import settings

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

# Configure pytest-django
pytest_plugins = ['pytest_django'] 