# Testing with Docker Compose

This project includes a separate Docker Compose configuration for running tests with pytest.

## Running Tests

The simplest way to run tests is to use the test-specific Docker Compose configuration:

```bash
docker-compose -f docker-compose.test.yml --profile test up --build --abort-on-container-exit
```

This command will:
- Start all required services (web, database, memcache)
- Build the test container with dev dependencies
- Run the test suite
- Exit automatically when tests complete

## Alternative Options

### Option 1: Run tests with existing services
If you already have the main services running:

```bash
# Start the main services (if not already running)
docker-compose up -d db memcache

# Run tests
docker-compose -f docker-compose.test.yml --profile test up test --abort-on-container-exit
```

### Option 2: Run tests locally
If you have the dependencies installed locally:

```bash
# Install dependencies
pip install -e .

# Run tests
pytest test_session.py -v
```

## Test Structure

The tests are written using pytest and include:

- **Session Authentication Flow**: Complete login → session check → protected access → logout → session clear
- **Individual Test Functions**: Each step of the authentication process is tested separately
- **Unauthorized Access**: Verifies that protected endpoints reject unauthenticated requests
- **URL Handling**: Uses `yarl.URL` for proper URL construction and manipulation

## Test Output

Tests use pytest's built-in reporting mechanism with:
- Verbose output (`-v`)
- Short traceback format (`--tb=short`)
- Logging for detailed information
- Clear pass/fail indicators

## Dependencies

The test environment includes:
- `pytest` - Testing framework
- `pytest-django` - Django integration for pytest
- `yarl` - URL handling library
- `requests` - HTTP client for API testing

## Configuration

- `pytest.ini` - Pytest configuration
- `conftest.py` - Django setup for pytest
- `docker-compose.test.yml` - Test-specific Docker Compose configuration

The test Docker Compose file references the main `docker-compose.yml` to avoid duplication of service definitions. 