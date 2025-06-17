#!/usr/bin/env python3
"""
Test script to demonstrate session-based authentication with memcache and CSRF protection.
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
def session_cookies_and_csrf():
    """Fixture to get authenticated session cookies and CSRF token."""
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    assert response.status_code == 200, f"Login failed: {response.text}"
    
    cookies = response.cookies
    response_data = response.json()
    csrf_token = response_data.get('csrf_token')
    
    logger.info(f"Session cookies obtained: {dict(cookies)}")
    logger.info(f"CSRF token obtained: {csrf_token}")
    
    return cookies, csrf_token

@pytest.fixture
def session_cookies(session_cookies_and_csrf):
    """Fixture to get authenticated session cookies."""
    cookies, _ = session_cookies_and_csrf
    return cookies

def test_login_creates_session():
    """Test that login creates a valid session and returns CSRF token."""
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    
    assert response.status_code == 200, f"Login failed: {response.text}"
    assert response.cookies, "No session cookies returned"
    
    response_data = response.json()
    assert "message" in response_data, "No message in response"
    assert "csrf_token" in response_data, "No CSRF token in response"
    assert response_data["csrf_token"], "CSRF token should not be empty"
    logger.info(f"Login successful: {response_data}")

def test_session_status_authenticated(session_cookies):
    """Test that session status returns correct information when authenticated."""
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=session_cookies)
    
    assert response.status_code == 200, f"Session status check failed: {response.text}"
    
    response_data = response.json()
    assert "authenticated" in response_data, "No authentication status in response"
    assert response_data["authenticated"] is True, "User should be authenticated"
    logger.info(f"Session status: {response_data}")

def test_authenticated_endpoint_access(session_cookies_and_csrf):
    """Test that authenticated endpoints work with valid session and CSRF token."""
    cookies, csrf_token = session_cookies_and_csrf
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email" / ""
    params = {"email": email}
    
    headers = {'X-CSRFToken': csrf_token}
    response = requests.get(str(url), params=params, cookies=cookies, headers=headers)
    
    assert response.status_code == 200, f"Authenticated endpoint access failed: {response.text}"
    
    response_data = response.json()
    assert "user" in response_data, "No user data in response"
    assert response_data["user"]["email"] == email, "Email mismatch"
    logger.info(f"Authenticated endpoint access successful: {response_data}")

def test_logout_clears_session(session_cookies_and_csrf):
    """Test that logout properly clears the session."""
    cookies, csrf_token = session_cookies_and_csrf
    
    # First verify we're authenticated
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=cookies)
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    
    # Now logout with CSRF token
    headers = {'X-CSRFToken': csrf_token}
    response = requests.post(str(BASE_URL / "users" / "logout" / ""), cookies=cookies, headers=headers)
    assert response.status_code == 200, f"Logout failed: {response.text}"
    
    response_data = response.json()
    assert "message" in response_data, "No message in logout response"
    logger.info(f"Logout successful: {response_data}")
    
    # Verify session is cleared
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=cookies)
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

def test_login_without_csrf():
    """Test that login works without CSRF tokens."""
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    # Login should work without any CSRF headers
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    assert response.status_code == 200, f"Login should work without CSRF token: {response.text}"
    
    response_data = response.json()
    assert "csrf_token" in response_data, "Login should return CSRF token for subsequent requests"
    assert response_data["csrf_token"], "CSRF token should not be empty"
    
    logger.info("Login endpoint correctly exempt from CSRF protection")

def test_csrf_protection():
    """Test that CSRF protection is working correctly."""
    # First login to get session cookies - should work without CSRF token
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    assert response.status_code == 200, f"Login failed: {response.text}"
    
    cookies = response.cookies
    response_data = response.json()
    csrf_token = response_data.get('csrf_token')
    assert csrf_token, "CSRF token should be returned after login"
    
    # Try to logout without CSRF token - should fail
    response = requests.post(str(BASE_URL / "users" / "logout" / ""), cookies=cookies)
    assert response.status_code == 403, f"Logout without CSRF token should return 403, got {response.status_code}"
    
    # Try to logout with invalid CSRF token - should fail
    headers = {'X-CSRFToken': 'invalid_token'}
    response = requests.post(str(BASE_URL / "users" / "logout" / ""), cookies=cookies, headers=headers)
    assert response.status_code == 403, f"Logout with invalid CSRF token should return 403, got {response.status_code}"
    
    # Try to logout with valid CSRF token - should succeed
    headers = {'X-CSRFToken': csrf_token}
    response = requests.post(str(BASE_URL / "users" / "logout" / ""), cookies=cookies, headers=headers)
    assert response.status_code == 200, f"Logout with valid CSRF token should succeed, got {response.status_code}"
    
    logger.info("CSRF protection working correctly - login exempt, other endpoints protected")

def test_session_authentication_flow():
    """Test the complete session authentication flow with CSRF protection."""
    login_data = {
        "email": "admin@yodaexample.click",
        "password": "yoda"
    }
    
    # Step 1: Login
    response = requests.post(str(BASE_URL / "users" / "login" / ""), json=login_data)
    assert response.status_code == 200, f"Login failed: {response.text}"
    
    cookies = response.cookies
    response_data = response.json()
    csrf_token = response_data.get('csrf_token')
    
    assert cookies, "No session cookies returned"
    assert csrf_token, "No CSRF token returned"
    logger.info("Step 1: Login successful")
    
    # Step 2: Check session status
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=cookies)
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    logger.info("Step 2: Session status confirmed")
    
    # Step 3: Access protected endpoint with CSRF token
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email" / ""
    params = {"email": email}
    headers = {'X-CSRFToken': csrf_token}
    
    response = requests.get(str(url), params=params, cookies=cookies, headers=headers)
    assert response.status_code == 200
    assert response.json()["user"]["email"] == email
    logger.info("Step 3: Protected endpoint accessed")
    
    # Step 4: Logout with CSRF token
    response = requests.post(str(BASE_URL / "users" / "logout" / ""), cookies=cookies, headers=headers)
    assert response.status_code == 200
    logger.info("Step 4: Logout successful")
    
    # Step 5: Verify session is cleared
    response = requests.get(str(BASE_URL / "users" / "session_status" / ""), cookies=cookies)
    assert response.status_code == 200
    assert response.json()["authenticated"] is False
    logger.info("Step 5: Session cleared confirmed")

def test_lookup_by_email_html_success():
    """Test that lookup_by_email_html returns proper HTML with user details."""
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email_html" / ""
    params = {"email": email}
    
    response = requests.get(str(url), params=params)
    
    assert response.status_code == 200, f"HTML lookup failed: {response.text}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    
    # Check that it's valid HTML
    assert "<html>" in html_content, "Response should contain HTML structure"
    assert "<head>" in html_content, "Response should contain head section"
    assert "<body>" in html_content, "Response should contain body section"
    assert "<table>" in html_content, "Response should contain table"
    
    # Check for user details
    assert email in html_content, "HTML should contain the user's email"
    assert "User Details" in html_content, "HTML should contain user details title"
    
    # Check for table structure
    assert "<th>Field Name</th>" in html_content, "HTML should contain field name header"
    assert "<th>Value</th>" in html_content, "HTML should contain value header"
    
    # Check for specific user fields that should be present
    assert "id" in html_content, "HTML should contain user ID field"
    assert "username" in html_content, "HTML should contain username field"
    assert "can_create_user" in html_content, "HTML should contain can_create_user field"
    assert "is_staff" in html_content, "HTML should contain is_staff field"
    assert "is_active" in html_content, "HTML should contain is_active field"
    
    logger.info("HTML lookup successful - proper HTML structure and user details returned")

def test_lookup_by_email_html_missing_email():
    """Test that lookup_by_email_html returns error HTML when email is missing."""
    url = BASE_URL / "users" / "lookup_by_email_html" / ""
    
    response = requests.get(str(url))
    
    assert response.status_code == 400, f"Missing email should return 400, got {response.status_code}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    
    # Check for error message
    assert "Error" in html_content, "HTML should contain error message"
    assert "Please provide an email address" in html_content, "HTML should contain email requirement message"
    assert "Usage:" in html_content, "HTML should contain usage instructions"
    
    logger.info("HTML lookup properly handles missing email parameter")

def test_lookup_by_email_html_user_not_found():
    """Test that lookup_by_email_html returns error HTML when user is not found."""
    email = "nonexistent@example.com"
    url = BASE_URL / "users" / "lookup_by_email_html" / ""
    params = {"email": email}
    
    response = requests.get(str(url), params=params)
    
    assert response.status_code == 404, f"User not found should return 404, got {response.status_code}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    
    # Check for error message
    assert "User Not Found" in html_content, "HTML should contain user not found message"
    assert email in html_content, "HTML should contain the requested email"
    
    logger.info("HTML lookup properly handles user not found case")

def test_lookup_by_email_html_no_authentication_required():
    """Test that lookup_by_email_html works without authentication (unlike JSON version)."""
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email_html" / ""
    params = {"email": email}
    
    # Should work without any authentication
    response = requests.get(str(url), params=params)
    
    assert response.status_code == 200, f"HTML lookup should work without auth, got {response.status_code}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    assert "<html>" in html_content, "Response should be valid HTML"
    assert email in html_content, "HTML should contain the user's email"
    
    logger.info("HTML lookup correctly accessible without authentication")

def test_lookup_by_email_html_jinja_success():
    """Test that lookup_by_email_html_jinja returns proper HTML with user details using Jinja template."""
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email_html_jinja" / ""
    params = {"email": email}
    
    response = requests.get(str(url), params=params)
    
    assert response.status_code == 200, f"Jinja HTML lookup failed: {response.text}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    
    # Check that it's valid HTML with proper structure
    assert "<!DOCTYPE html>" in html_content, "Response should contain DOCTYPE"
    assert "<html lang=\"en\">" in html_content, "Response should contain HTML with lang attribute"
    assert "<head>" in html_content, "Response should contain head section"
    assert "<body>" in html_content, "Response should contain body section"
    assert "<table>" in html_content, "Response should contain table"
    
    # Check for Jinja template specific elements
    assert "container" in html_content, "HTML should contain container class from template"
    assert "user-email" in html_content, "HTML should contain user-email class from template"
    assert "boolean-yes" in html_content or "boolean-no" in html_content, "HTML should contain boolean styling classes"
    
    # Check for user details
    assert email in html_content, "HTML should contain the user's email"
    assert "User Details" in html_content, "HTML should contain user details title"
    
    # Check for table structure
    assert "<th>Field Name</th>" in html_content, "HTML should contain field name header"
    assert "<th>Value</th>" in html_content, "HTML should contain value header"
    
    # Check for specific user fields that should be present
    assert "id" in html_content, "HTML should contain user ID field"
    assert "username" in html_content, "HTML should contain username field"
    assert "can_create_user" in html_content, "HTML should contain can_create_user field"
    assert "is_staff" in html_content, "HTML should contain is_staff field"
    assert "is_active" in html_content, "HTML should contain is_active field"
    
    # Check for enhanced styling from Jinja template
    assert "background-color: #f5f5f5" in html_content, "HTML should contain template styling"
    assert "box-shadow" in html_content, "HTML should contain enhanced CSS styling"
    
    logger.info("Jinja HTML lookup successful - proper template rendering and enhanced styling")

def test_lookup_by_email_html_jinja_missing_email():
    """Test that lookup_by_email_html_jinja returns error HTML when email is missing."""
    url = BASE_URL / "users" / "lookup_by_email_html_jinja" / ""
    
    response = requests.get(str(url))
    
    assert response.status_code == 400, f"Missing email should return 400, got {response.status_code}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    
    # Check for error message
    assert "Error" in html_content, "HTML should contain error message"
    assert "Please provide an email address" in html_content, "HTML should contain email requirement message"
    assert "lookup_by_email_html_jinja" in html_content, "HTML should contain correct endpoint in usage instructions"
    
    logger.info("Jinja HTML lookup properly handles missing email parameter")

def test_lookup_by_email_html_jinja_user_not_found():
    """Test that lookup_by_email_html_jinja returns error HTML when user is not found."""
    email = "nonexistent@example.com"
    url = BASE_URL / "users" / "lookup_by_email_html_jinja" / ""
    params = {"email": email}
    
    response = requests.get(str(url), params=params)
    
    assert response.status_code == 404, f"User not found should return 404, got {response.status_code}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    
    # Check for error message
    assert "User Not Found" in html_content, "HTML should contain user not found message"
    assert email in html_content, "HTML should contain the requested email"
    
    logger.info("Jinja HTML lookup properly handles user not found case")

def test_lookup_by_email_html_jinja_no_authentication_required():
    """Test that lookup_by_email_html_jinja works without authentication."""
    email = "admin@yodaexample.click"
    url = BASE_URL / "users" / "lookup_by_email_html_jinja" / ""
    params = {"email": email}
    
    # Should work without any authentication
    response = requests.get(str(url), params=params)
    
    assert response.status_code == 200, f"Jinja HTML lookup should work without auth, got {response.status_code}"
    assert response.headers['content-type'] == 'text/html', "Response should be HTML"
    
    html_content = response.text
    assert "<!DOCTYPE html>" in html_content, "Response should be valid HTML with DOCTYPE"
    assert email in html_content, "HTML should contain the user's email"
    
    logger.info("Jinja HTML lookup correctly accessible without authentication")

def test_lookup_by_email_html_vs_jinja_comparison():
    """Test that both HTML routes work and return similar content but with different styling."""
    email = "admin@yodaexample.click"
    
    # Test regular HTML route
    url_regular = BASE_URL / "users" / "lookup_by_email_html" / ""
    response_regular = requests.get(str(url_regular), params={"email": email})
    assert response_regular.status_code == 200
    
    # Test Jinja HTML route
    url_jinja = BASE_URL / "users" / "lookup_by_email_html_jinja" / ""
    response_jinja = requests.get(str(url_jinja), params={"email": email})
    assert response_jinja.status_code == 200
    
    # Both should contain the same user data
    assert email in response_regular.text, "Regular HTML should contain email"
    assert email in response_jinja.text, "Jinja HTML should contain email"
    
    # Both should contain table structure
    assert "<table>" in response_regular.text, "Regular HTML should contain table"
    assert "<table>" in response_jinja.text, "Jinja HTML should contain table"
    
    # Jinja version should have enhanced styling
    assert "container" in response_jinja.text, "Jinja HTML should have container class"
    assert "box-shadow" in response_jinja.text, "Jinja HTML should have enhanced CSS"
    
    # Regular version should have simpler styling
    assert "font-family: Arial" in response_regular.text, "Regular HTML should have basic styling"
    
    logger.info("Both HTML routes work correctly with appropriate styling differences")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"]) 