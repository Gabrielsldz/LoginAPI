from fastapi import APIRouter
from prisma.errors import UniqueViolationError
from prisma.errors import FieldNotFoundError
from datetime import timedelta
from jwt import ExpiredSignatureError, InvalidTokenError
import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from utils.utils import create_access_token, validate_captcha
from prismadb import prisma
from models.user import User
from utils.utils import encrypt_password
from utils.utils import check_password
from utils.utils import validate_token
import random
from fastapi import Form
import string
from fastapi.responses import StreamingResponse
from io import BytesIO
from utils.utils import generate_captcha_text, generate_captcha_image
from pydantic import BaseModel

router = APIRouter(prefix='/user')

def generate_invite_code(length=6):
    letters_and_digits = string.ascii_uppercase + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))




class CreateUserRequest(BaseModel):
    name: str
    password: str
    user_captcha: str

@router.post('/create_user')
async def create_user(user: CreateUserRequest):
    try:
        correct_captcha = captchas.get("captcha_text", None)
        print(correct_captcha)
        validate_captcha(user.user_captcha, correct_captcha)

        invite_code = generate_invite_code()
        while await prisma.user.find_unique(where={"invite_code": invite_code}):
            invite_code = generate_invite_code()

        user.password = encrypt_password(user.password)
        await prisma.user.create(data={"name": user.name, "password": user.password, "invite_code": invite_code})

    except UniqueViolationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username já existe.",
        )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro durante a criação do usuário.",
        )
    return 'Account created successfully! ' + user.name

@router.post('/create_user/{invite_code}')
async def register_with_invite(user: User, invite_code: str):
    try:

        inviter = await prisma.user.find_unique(where={"invite_code": invite_code})
        if not inviter:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código de convite inválido.",
            )


        new_invite_code = generate_invite_code()
        while await prisma.user.find_unique(where={"invite_code": new_invite_code}):
            new_invite_code = generate_invite_code()


        user.password = encrypt_password(user.password)

        await prisma.user.create(data={**user.dict(), "invite_code": new_invite_code})

        await prisma.user.update(
            where={
                "invite_code": invite_code
            },
            data={
                "invite_count": inviter.invite_count + 1
            }
        )

    except UniqueViolationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username já existe.",
        )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro durante a criação do usuário.",
        )

    return 'Account created successfully! ' + user.name



# @router.post('/register_new_account')
# async def create_user(user: User):
#     try:
#         user.password = encrypt_password(user.password)
#         await prisma.user.create(data=user.dict())
#     except UniqueViolationError:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Username ja existe.",
#         )
#     except Exception as e:
#         print(e)
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Ocorreu um erro durante a criacao do usuario.",
#         )
#     return 'Account created successfully!  ' + user.name


@router.post("/edit_user")
async def edit_user(user: User, request: Request):
    token = validate_token(request.headers)
    print(token)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Voce nao tem permissao para isso.",
        )
    else:
        try:
            decoded_token = jwt.decode(token, "batatafricacombanana", algorithms=["HS256"])
            print(decoded_token)
            print(f"Token é válido! Decodificado: {decoded_token}")
            if decoded_token["sub"] != user.email:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Voce nao tem permissao para isso.",
                )
        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Voce nao tem permissao para isso.",
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Voce nao tem permissao para isso.",
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Voce nao tem permissao para isso.",
            )

    try:
        print('SEXO')
        user.password = encrypt_password(user.password)
        await prisma.user.update(
            where={
                "email": user.email
            },
            data={
                "name": user.name,
                "age": user.age,
                "password": user.password,
                "email": user.email
            }
        )
    except FieldNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro durante a atualizacao do usuario.",
        )
    return {'name': user.name, 'age': user.age, 'password': user.password, 'email': user.email}


@router.get('/get_info')
async def get_info(request: Request):
    try:
        token = validate_token(request.headers)
        print(token)
        if token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Voce nao tem permissao para isso.",
            )
        else:
            try:
                decoded_token = jwt.decode(token, "batatafricacombanana", algorithms=["HS256"])
                user_email = decoded_token["sub"]
                try:
                    user = await prisma.user.find_unique(
                        where={
                            "email": user_email
                        }
                    )
                    return {"name": user.name, "email": user.email, "age": user.age,
                            "eventsInterested": user.eventsInterested}
                except Exception as e:
                    print(e)
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Voce nao tem permissao para isso.",
                    )
            except ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Voce nao tem permissao para isso.")
            except InvalidTokenError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Voce nao tem permissao para isso.")
                print("Token é inválido")
            except Exception as e:
                print(e)
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Voce nao tem permissao para isso.",
        )


@router.post("/login")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_captcha: str = Form(...)
):
    try:
        correct_captcha = captchas.get("captcha_text", None)
        validate_captcha(user_captcha, correct_captcha)

        password = encrypt_password(form_data.password)
        user = await prisma.user.find_unique(where={"name": form_data.username})

        if not user or not check_password(user.password, form_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="E-mail ou senha incorretos"
            )

        access_token = create_access_token(
            data={"sub": form_data.username}, expires_delta=timedelta(hours=1)
        )
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro durante o login."
        )
@router.post("/delete_user")
async def delete_user(request: Request):
    try:
        token = validate_token(request.headers)
        decoded_token = jwt.decode(token, "batatafricacombanana", algorithms=["HS256"])
        try:

            await prisma.user.delete(where={
                "email": decoded_token["sub"]
            })

        except Exception as e:
            print("Could not find user")
            print(e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Voce nao tem permissao para isso.",
            )

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Voce nao tem permissao para isso.",
        )


captchas = {}

@router.get("/captcha")
async def get_captcha():
    captcha_text = generate_captcha_text()
    captchas["captcha_text"] = captcha_text

    image = generate_captcha_image(captcha_text)
    buf = BytesIO()
    image.save(buf, format="PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")