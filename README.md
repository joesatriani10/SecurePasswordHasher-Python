# SecurePasswordHasher_Python

This is a simple Python project that demonstrates secure password hashing using PBKDF2 with SHA256.

---

## Overview

The project implements secure password hashing and verification with the following key features:

- **Secure Password Hashing:** Uses PBKDF2 with SHA256 to generate a secure hash.
- **Random Salt Generation:** A random salt is generated for each password, ensuring that even identical passwords produce different hashes.
- **Self-Contained Hash Format:** The generated hash string includes the iteration count, salt (Base64), and hash (Base64) in the format `iterations$salt$hash`.
- **Password Verification:** Recomputes the hash using the stored parameters to verify the input password.

---

## Features

- **PBKDF2 Implementation:** Uses 100,000 iterations by default to enhance security.
- **Random Salt:** Generates a 16-byte salt for each password.
- **Example Usage:** The main section of the script demonstrates how to hash and verify a password.

---

## Prerequisites

- Python 3.6 or later.
- It is recommended to use a virtual environment for dependency management.

---

## Usage Example

Below is an example of how to use the secure password hasher in Python:

```python
from secure_password_hasher import hash_password, verify_password

password = "Test"
hashed = hash_password(password)
print(f"Generated hash: {hashed}")

is_valid = verify_password(password, hashed)
print(f"Password valid: {is_valid}")
```

## Security Recommendations

- **High Iteration Count:**  
  Use a high number of iterations (e.g., 100,000 or more) to slow down brute-force attacks. Review and update this number periodically as hardware performance improves.

- **Unique, Random Salt:**  
  Always generate a new, random salt for each password to ensure that identical passwords produce different hashes.

- **Secure Storage Format:**  
  Store the iteration count, salt (Base64 encoded), and hash (Base64 encoded) together. This allows you to use the same parameters during password verification.

- **Use Established Libraries:**  
  For production environments, consider using well-tested libraries (e.g., bcrypt, Argon2) that offer additional security features.

- **Constant-Time Comparison:**  
  Implement constant-time comparison when verifying passwords to prevent timing attacks.

- **Secure Data Handling:**  
  Ensure that hashed passwords and salts are stored securely and that all data transmissions are encrypted.

- **Regular Security Reviews:**  
  Periodically review and update your password hashing mechanism and security measures according to the latest best practices.
