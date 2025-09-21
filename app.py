import os
import openai
from openai import OpenAI

from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status, APIRouter, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, TIMESTAMP, DECIMAL, BOOLEAN, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext

# --- Configuration --- #
import os
SQLALCHEMY_DATABASE_URL = "sqlite:///./compliance_app.db"
SECRET_KEY = "a_very_secret_key_for_jwt"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# AI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # Get from environment variable
if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)
else:
    client = None

# --- Database Setup --- #
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Models (models.py) --- #

role_permissions = Table('Role_Permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('Roles.role_id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('Permissions.permission_id'), primary_key=True)
)

analysis_frameworks = Table('Analysis_Frameworks',
    Base.metadata,
    Column('analysis_id', Integer, ForeignKey('Analyses.analysis_id'), primary_key=True),
    Column('framework_id', Integer, ForeignKey('Regulatory_Frameworks.framework_id'), primary_key=True)
)

analysis_custom_rules = Table('Analysis_Custom_Rules',
    Base.metadata,
    Column('analysis_id', Integer, ForeignKey('Analyses.analysis_id'), primary_key=True),
    Column('rule_id', Integer, ForeignKey('Custom_Rules.rule_id'), primary_key=True)
)

class Role(Base):
    __tablename__ = "Roles"
    role_id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    users = relationship("User", back_populates="role")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")

class Permission(Base):
    __tablename__ = "Permissions"
    permission_id = Column(Integer, primary_key=True, index=True)
    permission_name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")

class User(Base):
    __tablename__ = "Users"
    user_id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey('Roles.role_id'))
    status = Column(String(50), nullable=False, default='pending')
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    role = relationship("Role", back_populates="users")

class Document(Base):
    __tablename__ = "Documents"
    document_id = Column(Integer, primary_key=True, index=True)
    uploader_user_id = Column(Integer, ForeignKey('Users.user_id'))
    file_name = Column(String(255), nullable=False)
    extracted_text = Column(Text)
    upload_timestamp = Column(TIMESTAMP, default=datetime.utcnow)
    status = Column(String(50), default='uploaded')
    uploader = relationship("User")

class Analysis(Base):
    __tablename__ = "Analyses"
    analysis_id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey('Documents.document_id'))
    initiator_user_id = Column(Integer, ForeignKey('Users.user_id'))
    analysis_timestamp = Column(TIMESTAMP, default=datetime.utcnow)
    overall_compliance_score = Column(DECIMAL)
    document = relationship("Document")
    initiator = relationship("User")
    frameworks = relationship("RegulatoryFramework", secondary=analysis_frameworks)
    custom_rules = relationship("CustomRule", secondary=analysis_custom_rules)

class RegulatoryFramework(Base):
    __tablename__ = "Regulatory_Frameworks"
    framework_id = Column(Integer, primary_key=True, index=True)
    framework_name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)

class CustomRule(Base):
    __tablename__ = "Custom_Rules"
    rule_id = Column(Integer, primary_key=True, index=True)
    creator_user_id = Column(Integer, ForeignKey('Users.user_id'))
    rule_name = Column(String(255), nullable=False)
    conditions = Column(Text)
    severity = Column(String(50))
    is_active = Column(BOOLEAN, default=True)
    creator = relationship("User")

class Risk(Base):
    __tablename__ = "Risks"
    risk_id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey('Analyses.analysis_id'))
    risk_explanation = Column(Text)
    severity = Column(String(50))
    confidence_score = Column(DECIMAL)
    status = Column(String(50), default='identified')
    triggered_by_framework_id = Column(Integer, ForeignKey('Regulatory_Frameworks.framework_id'), nullable=True)
    triggered_by_rule_id = Column(Integer, ForeignKey('Custom_Rules.rule_id'), nullable=True)
    analysis = relationship("Analysis")
    suggestions = relationship("Suggestion", back_populates="risk")

class Suggestion(Base):
    __tablename__ = "Suggestions"
    suggestion_id = Column(Integer, primary_key=True, index=True)
    risk_id = Column(Integer, ForeignKey('Risks.risk_id'))
    suggested_text = Column(Text)
    status = Column(String(50), default='proposed')
    risk = relationship("Risk", back_populates="suggestions")

class AuditTrail(Base):
    __tablename__ = "Audit_Trail"
    log_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('Users.user_id'))
    action_type = Column(String(100), nullable=False)
    timestamp = Column(TIMESTAMP, default=datetime.utcnow)
    details = Column(Text)
    user = relationship("User")

class Report(Base):
    __tablename__ = "Reports"
    report_id = Column(Integer, primary_key=True, index=True)
    generator_user_id = Column(Integer, ForeignKey('Users.user_id'))
    report_type = Column(String(100))
    generation_timestamp = Column(TIMESTAMP, default=datetime.utcnow)
    file_path = Column(String(255))
    generator = relationship("User")


# --- Schemas (schemas.py) --- #

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str
    role_id: int

class UserInvite(BaseModel):
    email: EmailStr
    role_id: int

class UserUpdate(BaseModel):
    role_id: Optional[int] = None
    status: Optional[str] = None

class UserInDB(UserBase):
    user_id: int
    role_id: int
    status: str
    created_at: datetime

    class Config:
        orm_mode = True

class PermissionBase(BaseModel):
    permission_name: str
    description: Optional[str] = None

class PermissionInDB(PermissionBase):
    permission_id: int
    class Config:
        orm_mode = True

class RoleBase(BaseModel):
    role_name: str
    description: Optional[str] = None

class RoleCreate(RoleBase):
    permission_ids: List[int]

class RoleUpdate(RoleBase):
    permission_ids: Optional[List[int]] = None

class RoleInDB(RoleBase):
    role_id: int
    class Config:
        orm_mode = True

class RoleDetails(RoleInDB):
    permissions: List[PermissionInDB] = []

class DocumentBase(BaseModel):
    file_name: str
    status: str

class DocumentInDB(DocumentBase):
    document_id: int
    upload_timestamp: datetime
    extracted_text: Optional[str] = None
    class Config:
        orm_mode = True

class AnalysisCreate(BaseModel):
    framework_ids: List[int]
    custom_rule_ids: List[int]

class AnalysisInDB(BaseModel):
    analysis_id: int
    document_id: int
    analysis_timestamp: datetime
    overall_compliance_score: Optional[float] = None
    status: str = 'running'
    class Config:
        orm_mode = True

class SuggestionInDB(BaseModel):
    suggestion_id: int
    suggested_text: str
    status: str
    class Config:
        orm_mode = True

class RiskInDB(BaseModel):
    risk_id: int
    risk_explanation: str
    severity: str
    status: str
    suggestions: List[SuggestionInDB] = []
    class Config:
        orm_mode = True

class RiskUpdate(BaseModel):
    status: str

class SuggestionUpdate(BaseModel):
    status: str
    edited_suggested_text: Optional[str] = None

class FrameworkInDB(BaseModel):
    framework_id: int
    framework_name: str
    description: Optional[str] = None
    class Config:
        orm_mode = True

class CustomRuleBase(BaseModel):
    rule_name: str
    conditions: str
    severity: str
    is_active: bool

class CustomRuleCreate(CustomRuleBase):
    pass

class CustomRuleUpdate(CustomRuleBase):
    pass

class CustomRuleInDB(CustomRuleBase):
    rule_id: int
    class Config:
        orm_mode = True

class ReportCreate(BaseModel):
    report_type: str
    filters: Dict[str, Any]

class ReportInDB(BaseModel):
    report_id: int
    report_type: str
    generation_timestamp: datetime
    file_path: str
    class Config:
        orm_mode = True

class AuditLogInDB(BaseModel):
    log_id: int
    user_id: int
    action_type: str
    timestamp: datetime
    details: str
    class Config:
        orm_mode = True


# --- Security (auth.py) --- #
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

def analyze_document_with_ai(text_content):
    """Analyze document content using OpenAI for compliance insights"""
    if not client or not OPENAI_API_KEY:
        return {
            "risks": ["AI analysis unavailable - no API key configured"],
            "compliance_score": 0,
            "summary": "Document analysis requires OpenAI API key to be configured"
        }

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "You are a compliance expert. Analyze the following document for compliance risks, issues, and provide a compliance score (0-100). Focus on GDPR, privacy, security, and regulatory compliance. Return JSON format."
                },
                {
                    "role": "user",
                    "content": f"Analyze this document for compliance issues:\n\n{text_content[:4000]}"  # Limit to 4000 chars
                }
            ],
            max_tokens=500,
            temperature=0.3
        )

        analysis = response.choices[0].message.content

        # Try to extract JSON from the response
        try:
            # Look for JSON in the response
            import json
            import re
            json_match = re.search(r'\{.*\}', analysis, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                return parsed
            else:
                return {
                    "risks": ["Unable to parse AI analysis response"],
                    "compliance_score": 50,
                    "summary": "AI analysis completed but response format was unexpected"
                }
        except json.JSONDecodeError:
            return {
                "risks": ["AI analysis response was not valid JSON"],
                "compliance_score": 50,
                "summary": "AI analysis completed but could not be structured"
            }

    except Exception as e:
        return {
            "risks": [f"AI analysis failed: {str(e)}"],
            "compliance_score": 0,
            "summary": "AI analysis encountered an error"
        }

def get_current_active_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.role or current_user.role.role_name.lower() != 'administrator':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    if current_user.status != 'active':
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# --- Main Application and Routers --- #
app = FastAPI(title="ComplianceDB API")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files with proper path handling
app.mount("/static", StaticFiles(directory="css"), name="css")

# Create a custom HTML serving function to avoid conflicts
@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard():
    try:
        with open("html/dashboard_page.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard page not found</h1>", status_code=404)

@app.get("/documents", response_class=HTMLResponse)
def read_documents():
    try:
        with open("html/documents_list.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Documents page not found</h1>", status_code=404)

@app.get("/users", response_class=HTMLResponse)
def read_users_page():
    try:
        with open("html/user_management.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Users page not found</h1>", status_code=404)

@app.get("/roles", response_class=HTMLResponse)
def read_roles_page():
    try:
        with open("html/role_management.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Roles page not found</h1>", status_code=404)

@app.get("/rules", response_class=HTMLResponse)
def read_rules_page():
    try:
        with open("html/rules_management.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Rules page not found</h1>", status_code=404)

@app.get("/reports", response_class=HTMLResponse)
def read_reports_page():
    try:
        with open("html/reporting_page.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Reports page not found</h1>", status_code=404)

@app.get("/audit", response_class=HTMLResponse)
def read_audit_page():
    try:
        with open("html/audit_trail.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Audit page not found</h1>", status_code=404)

@app.get("/analysis", response_class=HTMLResponse)
def read_analysis_page():
    try:
        with open("html/analysis_results.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Analysis page not found</h1>", status_code=404)

@app.get("/alerts", response_class=HTMLResponse)
def read_alerts_page():
    try:
        with open("html/alerts_page.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Alerts page not found</h1>", status_code=404)

# Root route to serve dashboard
@app.get("/", response_class=HTMLResponse)
def read_root():
    with open("html/dashboard_page.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/login", response_class=HTMLResponse)
def read_login():
    with open("html/login_page.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Create default roles and permissions if they don't exist
    admin_role = db.query(Role).filter(Role.role_name == 'Administrator').first()
    if not admin_role:
        admin_role = Role(role_name='Administrator', description='Full system access')
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)
    user_role = db.query(Role).filter(Role.role_name == 'User').first()
    if not user_role:
        user_role = Role(role_name='User', description='Standard user access')
        db.add(user_role)
        db.commit()
        db.refresh(user_role)

    # Create a default admin user if none exists
    admin_user = db.query(User).filter(User.email == 'admin@example.com').first()
    if not admin_user:
        admin_user = User(
            email='admin@example.com',
            password_hash=get_password_hash('adminpassword'),
            role_id=admin_role.role_id,
            status='active'
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
    db.close()


# --- Auth Router --- #
auth_router = APIRouter()

@auth_router.post("/token", response_model=Token)
def login_for_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.status != 'active':
        raise HTTPException(status_code=400, detail="Inactive user")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Users Router --- #
users_router = APIRouter(prefix="/users", tags=["Users"])

@users_router.post("/invite", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
def invite_user(user_invite: UserInvite, db: Session = Depends(get_db), admin: User = Depends(get_current_active_admin_user)):
    db_user = get_user_by_email(db, email=user_invite.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    # In a real app, you would send an email and the user would set their own password.
    # For this example, we create a user with a placeholder password and 'pending' status.
    fake_password = 'default_password' # User would need to reset this
    new_user = User(
        email=user_invite.email, 
        password_hash=get_password_hash(fake_password), 
        role_id=user_invite.role_id, 
        status='pending'
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@users_router.get("", response_model=List[UserInDB])
def read_users(status: Optional[str] = None, role_id: Optional[int] = None, db: Session = Depends(get_db), admin: User = Depends(get_current_active_admin_user)):
    query = db.query(User)
    if status:
        query = query.filter(User.status == status)
    if role_id:
        query = query.filter(User.role_id == role_id)
    return query.all()

@users_router.get("/{user_id}", response_model=UserInDB)
def read_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_active_admin_user)):
    db_user = db.query(User).filter(User.user_id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@users_router.put("/{user_id}", response_model=UserInDB)
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db), admin: User = Depends(get_current_active_admin_user)):
    db_user = db.query(User).filter(User.user_id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user_update.role_id is not None:
        db_user.role_id = user_update.role_id
    if user_update.status is not None:
        db_user.status = user_update.status
    db.commit()
    db.refresh(db_user)
    return db_user

# --- Roles & Permissions Router --- #
roles_router = APIRouter(prefix="/roles", tags=["Roles & Permissions"])

@roles_router.post("", response_model=RoleInDB, status_code=status.HTTP_201_CREATED)
def create_role(role: RoleCreate, db: Session = Depends(get_db), admin: User = Depends(get_current_active_admin_user)):
    db_role = Role(role_name=role.role_name, description=role.description)
    permissions = db.query(Permission).filter(Permission.permission_id.in_(role.permission_ids)).all()
    if len(permissions) != len(role.permission_ids):
        raise HTTPException(status_code=400, detail="One or more permission IDs are invalid.")
    db_role.permissions = permissions
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role

@roles_router.get("", response_model=List[RoleInDB])
def get_roles(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Role).all()

@roles_router.get("/{role_id}", response_model=RoleDetails)
def get_role_details(role_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_role = db.query(Role).filter(Role.role_id == role_id).first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    return db_role

@roles_router.put("/{role_id}", response_model=RoleInDB)
def update_role(role_id: int, role_update: RoleUpdate, db: Session = Depends(get_db), admin: User = Depends(get_current_active_admin_user)):
    db_role = db.query(Role).filter(Role.role_id == role_id).first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    db_role.role_name = role_update.role_name
    db_role.description = role_update.description
    if role_update.permission_ids is not None:
        permissions = db.query(Permission).filter(Permission.permission_id.in_(role_update.permission_ids)).all()
        db_role.permissions = permissions
    db.commit()
    db.refresh(db_role)
    return db_role

@app.get("/permissions", response_model=List[PermissionInDB], tags=["Roles & Permissions"])
def get_permissions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Permission).all()

# --- Documents Router --- #
documents_router = APIRouter(prefix="/documents", tags=["Documents"])

@documents_router.post("/upload", response_model=DocumentInDB, status_code=status.HTTP_201_CREATED)
def upload_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    # Handle both authenticated and unauthenticated uploads
    uploader_id = current_user.user_id if current_user else None

    # In a real app, save the file to a storage system and perform OCR.
    # For this example, we'll just mock it.
    extracted_text = f"Mock extracted text from {file.filename}"

    # Use AI analysis if available
    if OPENAI_API_KEY and client:
        extracted_text = f"AI-analyzed content from {file.filename}. This document appears to be a compliance-related file."
        ai_analysis = analyze_document_with_ai(extracted_text)
    else:
        ai_analysis = {
            "risks": ["AI analysis unavailable - no API key configured"],
            "compliance_score": 75,
            "summary": "Document processed with basic analysis"
        }

    db_doc = Document(
        uploader_user_id=uploader_id,
        file_name=file.filename,
        extracted_text=extracted_text,
        status='processing'
    )
    db.add(db_doc)
    db.commit()
    db.refresh(db_doc)

    # Simulate processing completion
    db_doc.status = 'completed'
    db.commit()
    db.refresh(db_doc)
    return db_doc

@documents_router.get("", response_model=List[DocumentInDB])
def get_documents(page: int = 1, limit: int = 10, status: Optional[str] = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(Document)
    if status:
        query = query.filter(Document.status == status)
    return query.offset((page - 1) * limit).limit(limit).all()

@documents_router.get("/{document_id}", response_model=DocumentInDB)
def get_document_details(document_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_doc = db.query(Document).filter(Document.document_id == document_id).first()
    if not db_doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return db_doc

@documents_router.delete("/{document_id}", status_code=status.HTTP_200_OK)
def delete_document(document_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_active_admin_user)):
    db_doc = db.query(Document).filter(Document.document_id == document_id).first()
    if not db_doc:
        raise HTTPException(status_code=404, detail="Document not found")
    # Also delete associated analyses, risks, etc. (cascading delete)    
    db.delete(db_doc)
    db.commit()
    return {"message": "Document deleted successfully"}

# --- Analyses Router --- #
analyses_router = APIRouter(prefix="/analyses", tags=["Analyses"])

@documents_router.post("/{document_id}/analyses", response_model=AnalysisInDB, status_code=status.HTTP_202_ACCEPTED)
def initiate_analysis(document_id: int, analysis_create: AnalysisCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_doc = db.query(Document).filter(Document.document_id == document_id).first()
    if not db_doc:
        raise HTTPException(status_code=404, detail="Document not found")
    db_analysis = Analysis(
        document_id=document_id, 
        initiator_user_id=current_user.user_id
    )
    # Link frameworks and rules
    # ... (Logic to fetch and link frameworks/rules based on IDs)
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)
    # In a real app, this would trigger a background job. We'll just mock the result.
    db_analysis.overall_compliance_score = 85.5
    db_analysis.status = 'completed'
    db.commit()
    db.refresh(db_analysis)
    return db_analysis

@analyses_router.get("/{analysis_id}", response_model=AnalysisInDB)
def get_analysis_summary(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_analysis = db.query(Analysis).filter(Analysis.analysis_id == analysis_id).first()
    if not db_analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return db_analysis

@analyses_router.get("/{analysis_id}/results", response_model=List[RiskInDB])
def get_analysis_results(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    risks = db.query(Risk).filter(Risk.analysis_id == analysis_id).all()
    if not risks:
         # Check if analysis exists to differentiate between no risks and no analysis
        db_analysis = db.query(Analysis).filter(Analysis.analysis_id == analysis_id).first()
        if not db_analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
    return risks

# --- Risks & Suggestions Router --- #
risks_router = APIRouter(tags=["Risks & Suggestions"])

@risks_router.put("/risks/{risk_id}", response_model=RiskInDB)
def update_risk_status(risk_id: int, risk_update: RiskUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_risk = db.query(Risk).filter(Risk.risk_id == risk_id).first()
    if not db_risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    db_risk.status = risk_update.status
    db.commit()
    db.refresh(db_risk)
    return db_risk

@risks_router.put("/suggestions/{suggestion_id}", response_model=SuggestionInDB)
def update_suggestion(suggestion_id: int, suggestion_update: SuggestionUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_suggestion = db.query(Suggestion).filter(Suggestion.suggestion_id == suggestion_id).first()
    if not db_suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    db_suggestion.status = suggestion_update.status
    if suggestion_update.edited_suggested_text:
        db_suggestion.suggested_text = suggestion_update.edited_suggested_text
    db.commit()
    db.refresh(db_suggestion)
    return db_suggestion

# --- Rules Router --- #
rules_router = APIRouter(prefix="/rules", tags=["Rules"])

@rules_router.get("/frameworks", response_model=List[FrameworkInDB])
def get_frameworks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(RegulatoryFramework).all()

@rules_router.post("/custom", response_model=CustomRuleInDB, status_code=status.HTTP_201_CREATED)
def create_custom_rule(rule: CustomRuleCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_rule = CustomRule(**rule.dict(), creator_user_id=current_user.user_id)
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@rules_router.get("/custom", response_model=List[CustomRuleInDB])
def get_custom_rules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(CustomRule).all()

@rules_router.get("/custom/{rule_id}", response_model=CustomRuleInDB)
def get_custom_rule(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_rule = db.query(CustomRule).filter(CustomRule.rule_id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return db_rule

@rules_router.put("/custom/{rule_id}", response_model=CustomRuleInDB)
def update_custom_rule(rule_id: int, rule_update: CustomRuleUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_rule = db.query(CustomRule).filter(CustomRule.rule_id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for key, value in rule_update.dict().items():
        setattr(db_rule, key, value)
    db.commit()
    db.refresh(db_rule)
    return db_rule

# --- Reports Router --- #
reports_router = APIRouter(prefix="/reports", tags=["Reports"])

@reports_router.post("", response_model=ReportInDB)
def generate_report(report_create: ReportCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Mock report generation
    file_path = f"/reports/report_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    db_report = Report(
        generator_user_id=current_user.user_id,
        report_type=report_create.report_type,
        file_path=file_path
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report

@reports_router.get("", response_model=List[ReportInDB])
def get_reports(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Report).all()

# --- Audit Trail Router ---
@app.get("/audit-trail", response_model=List[AuditLogInDB], tags=["Audit Trail"])
def get_audit_trail(
    user_id: Optional[int] = None, 
    start_date: Optional[datetime] = None, 
    end_date: Optional[datetime] = None, 
    action_type: Optional[str] = None,
    db: Session = Depends(get_db), 
    admin: User = Depends(get_current_active_admin_user)
):
    query = db.query(AuditTrail)
    if user_id:
        query = query.filter(AuditTrail.user_id == user_id)
    if start_date:
        query = query.filter(AuditTrail.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditTrail.timestamp <= end_date)
    if action_type:
        query = query.filter(AuditTrail.action_type == action_type)
    return query.all()

# --- Include Routers --- #
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(documents_router)
app.include_router(analyses_router)
app.include_router(risks_router)
app.include_router(rules_router)
app.include_router(reports_router) 