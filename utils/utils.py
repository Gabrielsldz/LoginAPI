from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from captcha.image import ImageCaptcha
import random
import string
from fastapi import HTTPException, status

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, "batatafricacombanana", algorithm="HS256")
    return encoded_jwt


def encrypt_password(password: str):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    # return {"hash_password": hashed_password, "salt": salt}
    return hashed_password.decode()


def check_password(hashed_password: str, password: str):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def validate_token(headers):
    authorization_header = headers.get("authorization")
    token = authorization_header[7:] if authorization_header and authorization_header.startswith("Bearer ") else None
    return token


def generate_captcha_text(length=6):
    letters_and_digits = string.ascii_uppercase + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def generate_captcha_image(text):
    image = ImageCaptcha(width=280, height=90)
    captcha_image = image.generate_image(text)
    return captcha_image

def validate_captcha(user_captcha, correct_captcha):
    if (user_captcha.lower()) != correct_captcha.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CAPTCHA incorreto.",
        )