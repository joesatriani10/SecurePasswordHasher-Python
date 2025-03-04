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
