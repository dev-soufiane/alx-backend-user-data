#!/usr/bin/env python3
"""
Password encryption and validation
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Encrypt password using bcrypt.
    Args:
        password: Password to encrypt.
    Returns:
        Encrypted password as bytes.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if password matches hashed version.
    Args:
        hashed_password: Encrypted password (bytes).
        password: Password to verify.
    Returns:
        True if password matches, else False.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
