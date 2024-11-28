from pydantic import BaseModel
from typing import Optional

class User(BaseModel):
    name: str
    password: str
    invite_code: Optional[str] = None
    invite_count: Optional[int] = 0
