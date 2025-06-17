#!/usr/bin/env python3
"""
Test script to demonstrate session-based authentication with memcache.
"""

import pytest
import requests
import json
import logging
import os
from yarl import URL

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Use environment variable for base URL, default to localhost for local development
BASE_URL = URL(os.getenv("TEST_BASE_URL", "http://localhost:8000/api"))

@pytest.fixture
def session_cookies():
    """Fixture to get authenticated session cookies."""
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    assert response.status_code == 200, f"Login failed: {response.text}"
    
    cookies = response.cookies
    logger.info(f"Session cookies obtained: {dict(cookies)}")
    return cookies

def test_login_creates_session():
    """Test that login creates a valid session."""
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    
    assert response.status_code == 200, f"Login failed: {response.text}"
    assert response.cookies, "No session cookies returned"
    
    response_data = response.json()
    assert "message" in response_data, "No message in response"
    logger.info(f"Login successful: {response_data}")

def test_session_status_authenticated(session_cookies):
    """Test that session status returns correct information when authenticated."""
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=session_cookies)
    
    assert response.status_code == 200, f"Session status check failed: {response.text}"
    
    response_data = response.json()
    assert "authenticated" in response_data, "No authentication status in response"
    assert response_data["authenticated"] is True, "User should be authenticated"
    logger.info(f"Session status: {response_data}")

def test_authenticated_endpoint_access(session_cookies):
    """Test that authenticated endpoints work with valid session."""
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email" / ""
    params = {"email": email}
    
    response = requests.get(str(url), params=params, cookies=session_cookies)
    
    assert response.status_code == 200, f"Authenticated endpoint access failed: {response.text}"
    
    response_data = response.json()
    assert "user" in response_data, "No user data in response"
    assert response_data["user"]["email"] == email, "Email mismatch"
    logger.info(f"Authenticated endpoint access successful: {response_data}")

def test_logout_clears_session(session_cookies):
    """Test that logout properly clears the session."""
    # First verify we're authenticated
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=session_cookies)
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    
    # Now logout
    response = requests.post(str(BASE_URL / "users" / "logout" / ""), cookies=session_cookies)
    assert response.status_code == 200, f"Logout failed: {response.text}"
    
    response_data = response.json()
    assert "message" in response_data, "No message in logout response"
    logger.info(f"Logout successful: {response_data}")
    
    # Verify session is cleared
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=session_cookies)
    assert response.status_code == 200
    assert response.json()["authenticated"] is False, "Session should be cleared after logout"

def test_unauthorized_access_rejected():
    """Test that unauthorized access is properly rejected."""
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email" / ""
    params = {"email": email}
    
    response = requests.get(str(url), params=params)
    
    assert response.status_code == 403, f"Unauthorized access should return 403, got {response.status_code}"
    
    response_data = response.json()
    assert "detail" in response_data, "No error message in unauthorized response"
    logger.info(f"Unauthorized access properly rejected: {response_data}")

def test_session_authentication_flow():
    """Test the complete session authentication flow."""
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    # Step 1: Login
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    assert response.status_code == 200, f"Login failed: {response.text}"
    
    cookies = response.cookies
    assert cookies, "No session cookies returned"
    logger.info("Step 1: Login successful")
    
    # Step 2: Check session status
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=cookies)
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    logger.info("Step 2: Session status confirmed")
    
    # Step 3: Access protected endpoint
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email" / ""
    params = {"email": email}
    
    response = requests.get(str(url), params=params, cookies=cookies)
    assert response.status_code == 200
    assert response.json()["user"]["email"] == email
    logger.info("Step 3: Protected endpoint accessed")
    
    # Step 4: Logout
    response = requests.post(str(BASE_URL / "users" / "logout" / ""), cookies=cookies)
    assert response.status_code == 200
    logger.info("Step 4: Logout successful")
    
    # Step 5: Verify session is cleared
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=cookies)
    assert response.status_code == 200
    assert response.json()["authenticated"] is False
    logger.info("Step 5: Session cleared confirmed")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"]) 