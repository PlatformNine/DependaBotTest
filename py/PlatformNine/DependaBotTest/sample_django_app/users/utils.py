import bcrypt

def hash_password(raw_password: str) -> str:
    """
    Consistently hash a password using bcrypt.
    This function is used by both the model and migrations to ensure consistent hashing.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(raw_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(raw_password: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored hash.
    This function is used by both the model and migrations to ensure consistent verification.
    """
    try:
        return bcrypt.checkpw(raw_password.encode('utf-8'), stored_hash.encode('utf-8'))
    except (ValueError, AttributeError):
        return False 