import hashlib
import os
import base64

def hash_password(password: str, iterations: int = 100000) -> str:
    """
    Generates a secure hash for the password using PBKDF2 with SHA256.
    Output format: iterations$salt(Base64)$hash(Base64)
    """
    # Generate a random salt
    salt = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')
    return f"{iterations}${salt_b64}${hash_b64}"

def verify_password(password: str, hashed: str) -> bool:
    """
    Verifies if the provided password matches the stored hash.
    """
    try:
        iterations_str, salt_b64, hash_b64 = hashed.split('$')
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64)
        stored_hash = base64.b64decode(hash_b64)
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return new_hash == stored_hash
    except Exception:
        return False

# Example usage
if __name__ == "__main__":
    password = "Test"
    hashed = hash_password(password)
    print(f"Generated hash: {hashed}")
    print("Password valid:", verify_password(password, hashed))
