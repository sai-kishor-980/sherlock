"""
Security, Cryptographic Hashing, Password Hashing, and JWT Token Utilities.
"""

import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import jwt, JWTError, ExpiredSignatureError
import bcrypt
if not hasattr(bcrypt, "__about__"):
    class BcryptAbout:
        __version__ = getattr(bcrypt, "__version__", "4.0.1")
    bcrypt.__about__ = BcryptAbout

from app.core.config import settings


def generate_hmac(data: bytes, secret_key: str = None) -> str:
    """
    Generates HMAC token for data using SHA256.
    """
    key = (secret_key or settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, expected_hmac: str, secret_key: str = None) -> bool:
    """
    Verifies HMAC token against generated HMAC for given data.
    """
    calculated = generate_hmac(data, secret_key)
    return hmac.compare_digest(calculated, expected_hmac)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a stored bcrypt hash.
    """
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """
    Generates bcrypt hash for plain password.
    """
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates JWT access token with expiration time and payload claims.
    """
    to_encode = data.copy()
    now = datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,
        "iat": now
    })
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates JWT access token.
    Raises ExpiredSignatureError if the token expiration timestamp has passed.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except ExpiredSignatureError:
        raise
    except JWTError:
        return None
