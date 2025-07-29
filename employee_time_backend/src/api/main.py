import os
from typing import List, Optional
from fastapi import (
    FastAPI, Depends, HTTPException, status, Request, Response
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, date
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import uuid
import asyncpg

# ---------------- ENV VARS & SETTINGS -----------------
# You must set these environment variables in your .env file!
DB_HOST = os.environ.get("EMPLOYEE_TIME_DB_HOST")
DB_PORT = os.environ.get("EMPLOYEE_TIME_DB_PORT")
DB_USER = os.environ.get("EMPLOYEE_TIME_DB_USER")
DB_PASSWORD = os.environ.get("EMPLOYEE_TIME_DB_PASSWORD")
DB_NAME = os.environ.get("EMPLOYEE_TIME_DB_NAME")
JWT_SECRET_KEY = os.environ.get("EMPLOYEE_TIME_JWT_SECRET", "changeme123")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("EMPLOYEE_TIME_JWT_EXPIRE", 60 * 24))
# -----------------------------------------------------

# ---------------- PWD CONTEXT & OAUTH -------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")
# --------------------------------------------------------------

# ----------------- MODELS -------------------------------------

class Token(BaseModel):
    """JWT token returned after login"""
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Data extracted from a JWT token."""
    user_id: Optional[int] = None
    email: Optional[EmailStr] = None


class UserBase(BaseModel):
    """Base user info."""
    email: EmailStr = Field(..., description="Employee email address")
    full_name: Optional[str] = Field(None, description="Employee full name")


class UserCreate(UserBase):
    """For creating a user during registration."""
    password: str = Field(..., min_length=6)
    employee_id: Optional[str] = Field(None, description="Employee identifier")


class UserOut(UserBase):
    """For displaying user info."""
    id: int
    employee_id: str
    is_active: bool


class UserProfile(UserBase):
    """User profile details."""
    employee_id: str
    department: Optional[str] = None
    position: Optional[str] = None
    hire_date: Optional[date] = None
    is_active: bool


class TimecardEntry(BaseModel):
    """An entry in a timecard."""
    id: Optional[int] = None
    date: date = Field(..., description="Date of work")
    hours_worked: float = Field(..., gt=0, lt=24)
    project_code: Optional[str] = Field(None, description="Optional code for project or task")
    notes: Optional[str] = None


class SubmitTimecardRequest(BaseModel):
    """Request for submitting multiple timecard entries at once."""
    entries: List[TimecardEntry]


class Payslip(BaseModel):
    """Pay and deductions for a period."""
    pay_period_start: date
    pay_period_end: date
    gross_pay: float
    total_hours: float
    taxes: float
    deductions: float
    net_pay: float
    details: Optional[str]


# ----------- DATABASE CONNECTION POOL -----------
db_pool = None


async def get_db():
    """
    Dependency - get a db connection from the pool.
    """
    global db_pool
    if db_pool is None:
        db_pool = await asyncpg.create_pool(
            user=DB_USER, password=DB_PASSWORD,
            database=DB_NAME, host=DB_HOST, port=DB_PORT, min_size=1, max_size=3
        )
    async with db_pool.acquire() as conn:
        yield conn

# ----------- PASSWORD HANDLING -----------


def verify_password(plain_password, hashed_password):
    """Check password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """Encrypt password."""
    return pwd_context.hash(password)


# ----------- JWT UTILS -----------


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "sub": str(data["user_id"])})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme), db=Depends(get_db)
) -> UserOut:
    """
    PUBLIC_INTERFACE
    Dependency that extracts the user from the JWT, checks active status.
    Raises 401 if unauthenticated or user not found.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    query = "SELECT id, email, full_name, employee_id, is_active FROM users WHERE id=$1"
    row = await db.fetchrow(query, user_id)
    if row is None or not row["is_active"]:
        raise credentials_exception

    return UserOut(**row)


# -------------- FASTAPI APP CREATION ------------

openapi_tags = [
    {"name": "auth", "description": "Authentication & login endpoints"},
    {"name": "timecard", "description": "Timecard management"},
    {"name": "payroll", "description": "Pay breakdown, tax, and payroll info"},
    {"name": "profile", "description": "User profile management"},
]

app = FastAPI(
    title="Employee Time and Payroll API",
    description="APIs for employee authentication, timecards, payroll, and profiles.",
    version="0.1.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In prod change to frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------- ROUTES ---------------------

@app.get("/", tags=["misc"])
def health_check():
    """
    PUBLIC_INTERFACE
    Health check endpoint.
    Returns 200 if backend is running.
    """
    return {"message": "Healthy"}


# ------------------ AUTH ENDPOINTS ------------------

@app.post("/auth/token", response_model=Token, tags=["auth"], summary="Login and obtain a JWT", description="Authenticate user via email & password. Returns a JWT token.")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Authenticates user, returns a JWT token for use in Authorization header.
    """
    query = "SELECT * FROM users WHERE email=$1"
    user = await db.fetchrow(query, form_data.username)
    if not user or not user["is_active"]:
        raise HTTPException(status_code=400, detail="Incorrect email or inactive user")
    if not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect password")

    access_token = create_access_token(data={"user_id": user["id"], "email": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/register", response_model=UserOut, tags=["auth"], summary="Register New User", description="Creates a new user/employee account.")
async def register(user: UserCreate, db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Register a new employee.
    """
    # Unique email
    exists = await db.fetchval("SELECT COUNT(*) FROM users WHERE email=$1", user.email)
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = get_password_hash(user.password)
    eid = user.employee_id or str(uuid.uuid4())
    row = await db.fetchrow(
        """INSERT INTO users (email, full_name, password_hash, employee_id, is_active)
           VALUES ($1,$2,$3,$4,true)
           RETURNING id, email, full_name, employee_id, is_active
        """,
        user.email, user.full_name, password_hash, eid
    )
    return UserOut(**row)


# ------------------ PROFILE ------------------
@app.get("/profile/me", response_model=UserProfile, tags=["profile"], summary="Get My Profile")
async def get_my_profile(current_user: UserOut = Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Returns current employee's profile (with extended info).
    """
    row = await db.fetchrow(
        """SELECT email, full_name, employee_id, department, position, hire_date, is_active FROM users WHERE id=$1""",
        current_user.id
    )
    if row is None:
        raise HTTPException(status_code=404, detail="User profile not found")
    return UserProfile(**row)


@app.put("/profile/me", response_model=UserProfile, tags=["profile"], summary="Update My Profile")
async def update_my_profile(profile: UserProfile, current_user: UserOut = Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Updates current employee's profile.
    """
    q = """UPDATE users SET full_name=$1, department=$2, position=$3, hire_date=$4
           WHERE id=$5 RETURNING email, full_name, employee_id, department, position, hire_date, is_active
        """
    row = await db.fetchrow(q, profile.full_name, profile.department, profile.position, profile.hire_date, current_user.id)
    if row is None:
        raise HTTPException(status_code=404, detail="Could not update profile")
    return UserProfile(**row)

# ---------------- TIME ENTRY ENDPOINTS ---------------

@app.get("/timecard/me", response_model=List[TimecardEntry], tags=["timecard"], summary="Get My Timecards", description="Get all timecard entries for current user for optionally a time period")
async def get_my_timecards(
    start: Optional[date] = None,
    end: Optional[date] = None,
    current_user: UserOut = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Get all timecard entries for current user in optional date range.
    """
    if start and end:
        rows = await db.fetch(
            "SELECT id, date, hours_worked, project_code, notes FROM timecards WHERE user_id=$1 AND date BETWEEN $2 AND $3 ORDER BY date DESC",
            current_user.id, start, end)
    else:
        rows = await db.fetch(
            "SELECT id, date, hours_worked, project_code, notes FROM timecards WHERE user_id=$1 ORDER BY date DESC",
            current_user.id)
    return [TimecardEntry(**row) for row in rows]


@app.post("/timecard/me", response_model=List[TimecardEntry], tags=["timecard"], summary="Submit My Timecard", description="Submit one or more timecard entries for the authenticated user")
async def submit_timecard(
    req: SubmitTimecardRequest,
    current_user: UserOut = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Submit timecard entries for current user. Returns created entries.
    """
    values = []
    for e in req.entries:
        values.append((current_user.id, e.date, e.hours_worked, e.project_code, e.notes))
    inserted = []
    async with db.transaction():
        for user_id, dt, hrs, pcode, notes in values:
            row = await db.fetchrow(
                """INSERT INTO timecards (user_id, date, hours_worked, project_code, notes)
                   VALUES ($1, $2, $3, $4, $5)
                   RETURNING id, date, hours_worked, project_code, notes
                """,
                user_id, dt, hrs, pcode, notes
            )
            inserted.append(TimecardEntry(**row))
    return inserted

# ------------------ PAYROLL & PAYSLIPS ----------------

@app.get("/payslip/me", response_model=Payslip, tags=["payroll"], summary="Get My Latest Payslip", description="Retrieve most recent payroll calculation for current user.")
async def get_my_latest_payslip(
    current_user: UserOut = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Get the most recent payslip for current user.
    """
    # Dummy payroll calculation.
    # In reality, this would be calculated with a payroll engine & tax logic.
    time_entries = await db.fetch(
        "SELECT hours_worked FROM timecards WHERE user_id=$1 AND date >= (current_date - interval '14 days')",
        current_user.id
    )
    total_hours = sum(row['hours_worked'] for row in time_entries)
    hourly_rate = await db.fetchval("SELECT hourly_rate FROM users WHERE id=$1", current_user.id) or 20.0
    gross = total_hours * hourly_rate
    taxes = gross * 0.18
    deductions = gross * 0.04
    payslip = Payslip(
        pay_period_start=(datetime.now() - timedelta(days=14)).date(),
        pay_period_end=datetime.now().date(),
        gross_pay=gross,
        total_hours=total_hours,
        taxes=taxes,
        deductions=deductions,
        net_pay=gross - taxes - deductions,
        details="Payroll period: two weeks. Taxes: 18%, Deductions: 4%."
    )
    return payslip

@app.get("/payslip/me/all", response_model=List[Payslip], tags=["payroll"], summary="Get Payslip History", description="Retrieve all payslips for current user (dummy historical intervals).")
async def list_my_payslips(
    current_user: UserOut = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Returns a list of historical payslip breakdowns for current user.
    """
    # For demo only - derive every two weeks as a fake payroll history.
    payslips: List[Payslip] = []
    q = "SELECT min(date), max(date) FROM timecards WHERE user_id=$1"
    minmax = await db.fetchrow(q, current_user.id)
    if not minmax or not minmax['min'] or not minmax['max']:
        return []
    dt = minmax['min']
    end = minmax['max']
    while dt < end:
        window_end = dt + timedelta(days=13)
        q = """SELECT COALESCE(sum(hours_worked),0) as hours
               FROM timecards WHERE user_id=$1 AND date BETWEEN $2 AND $3"""
        hrs = await db.fetchval(q, current_user.id, dt, window_end) or 0
        hourly_rate = await db.fetchval("SELECT hourly_rate FROM users WHERE id=$1", current_user.id) or 20.0
        gross = hrs * hourly_rate
        taxes = gross * 0.18
        deductions = gross * 0.04
        payslips.append(Payslip(
            pay_period_start=dt,
            pay_period_end=window_end,
            gross_pay=gross,
            total_hours=hrs,
            taxes=taxes,
            deductions=deductions,
            net_pay=gross-taxes-deductions,
            details="Historical auto-calculated entry (2 week interval)."
        ))
        dt = window_end + timedelta(days=1)
    return payslips

# --------- UTIL ENDPOINTS ---------

@app.get("/docs/websocket", tags=["misc"], summary="WebSocket Usage Help")
def websocket_help():
    """
    PUBLIC_INTERFACE
    This API does not provide WebSocket endpoints. Use HTTP(S) REST endpoints only.
    """
    return {"note": "No websocket endpoints. Use REST/HTTPS URLs."}

# --------- ERROR HANDLING ---------
@app.exception_handler(asyncpg.PostgresError)
async def pg_error_handler(request: Request, exc: asyncpg.PostgresError):
    return Response(
        status_code=500,
        content=f"Database error: {exc}",
        media_type="application/json"
    )
