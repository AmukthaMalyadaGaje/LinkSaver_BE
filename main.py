from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, HttpUrl
from datetime import datetime, timedelta
from typing import Optional, List
from passlib.context import CryptContext
from jose import JWTError, jwt
from bson import ObjectId
import urllib.parse
import httpx
import os

# Initialize FastAPI app
app = FastAPI()

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite's default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security configurations
SECRET_KEY = "your-secret-key-here"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# MongoDB configuration
MONGO_URL = "mongodb://localhost:27017"
db_client = AsyncIOMotorClient(MONGO_URL)
db = db_client.linksaver_db

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Helper function to convert ObjectId to string
def serialize_document(doc):
    if doc.get('_id'):
        doc['_id'] = str(doc['_id'])
    if doc.get('user_id'):
        doc['user_id'] = str(doc['user_id'])
    return doc

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    email: str
    hashed_password: str

class UserCreate(BaseModel):
    email: str
    password: str

class Bookmark(BaseModel):
    url: HttpUrl
    title: str
    favicon: Optional[str] = None
    summary: Optional[str] = None
    created_at: datetime = datetime.now()
    tags: List[str] = []

class BookmarkCreate(BaseModel):
    url: HttpUrl
    summary: Optional[str] = None

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await db.users.find_one({"email": token_data.username})
    if user is None:
        raise credentials_exception
    return serialize_document(user)

# Authentication endpoints
@app.post("/register")
async def register_user(user: UserCreate):
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    hashed_password = get_password_hash(user.password)
    user_dict = {
        "email": user.email,
        "hashed_password": hashed_password
    }

    result = await db.users.insert_one(user_dict)
    user_dict["_id"] = result.inserted_id
    return {"message": "User registered successfully", "status": "success"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Bookmark endpoints
@app.post("/bookmarks")
async def create_bookmark(bookmark: BookmarkCreate, current_user: dict = Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(str(bookmark.url))
            response.raise_for_status()

            bookmark_data = {
                "url": str(bookmark.url),
                "title": "Untitled",  # You would parse this from response
                "favicon": f"{bookmark.url.scheme}://{bookmark.url.host}/favicon.ico",
                "summary": bookmark.summary or "Summary unavailable",
                "user_id": ObjectId(current_user["_id"]),
                "created_at": datetime.now(),
                "tags": []
            }

            result = await db.bookmarks.insert_one(bookmark_data)
            bookmark_data["_id"] = str(result.inserted_id)
            bookmark_data["user_id"] = str(bookmark_data["user_id"])
            return bookmark_data

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error processing URL: {str(e)}"
            )

@app.get("/bookmarks")
async def get_bookmarks(current_user: dict = Depends(get_current_user)):
    cursor = db.bookmarks.find({"user_id": ObjectId(current_user["_id"])})
    bookmarks = []
    async for bookmark in cursor:
        bookmarks.append(serialize_document(bookmark))
    return bookmarks

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
