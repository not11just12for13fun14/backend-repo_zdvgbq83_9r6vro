import os
from datetime import datetime, timedelta, date
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Hospital as HospitalSchema, Donor as DonorSchema, DonationHistory as DonationSchema, Inventory as InventorySchema, BloodRequest as BloodRequestSchema, Notification as NotificationSchema, Certificate as CertificateSchema

# ------------------------------------
# App and Security Setup
# ------------------------------------
app = FastAPI(title="HEMO LINK API", version="1.0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ------------------------------------
# Helpers
# ------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None

class RegisterPayload(BaseModel):
    email: EmailStr
    password: str
    role: str
    name: Optional[str] = None
    phone: Optional[str] = None
    theme: Optional[str] = "light"
    # Hospital registration (optional based on role)
    hospital_name: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    pincode: Optional[str] = None
    contact_numbers: Optional[List[str]] = None
    blood_bank_details: Optional[str] = None

class LoginPayload(BaseModel):
    email: EmailStr
    password: str

class UpdateStatusPayload(BaseModel):
    status: str

class InventoryUpdatePayload(BaseModel):
    units: Dict[str, int]

class DonationCompletePayload(BaseModel):
    donor_id: str
    hospital_id: str
    units: float = 1.0
    notes: Optional[str] = None

# BSON/ObjectId helpers
class PyObjectId(ObjectId):
    @staticmethod
    def __get_validators__():
        yield PyObjectId.validate

    @staticmethod
    def validate(v):
        if isinstance(v, ObjectId):
            return v
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

def oid(obj: Any) -> str:
    try:
        return str(obj)
    except Exception:
        return obj

# Auth utilities

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
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
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception

    user = db["user"].find_one({"_id": ObjectId(token_data.user_id)})
    if not user:
        raise credentials_exception
    user["_id"] = str(user["_id"])
    return user


def require_role(user, roles: List[str]):
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

# ------------------------------------
# Health & Test
# ------------------------------------
@app.get("/")
def read_root():
    return {"message": "HEMO LINK API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response

# ------------------------------------
# Auth & Registration
# ------------------------------------
@app.post("/auth/register", response_model=Token)
def register(payload: RegisterPayload):
    role = payload.role.lower()
    if role not in ["admin", "hospital", "bloodbank", "donor"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    # email unique
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=409, detail="Email already registered")

    hospital_id = None
    # If hospital/bloodbank role and hospital details provided, create hospital
    if role in ["hospital", "bloodbank"] and payload.hospital_name:
        hospital = HospitalSchema(
            name=payload.hospital_name,
            address=payload.address,
            city=payload.city,
            state=payload.state,
            pincode=payload.pincode,
            contact_numbers=payload.contact_numbers or [],
            blood_bank_details=payload.blood_bank_details,
        )
        hospital_id = create_document("hospital", hospital)
    
    user_doc = UserSchema(
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        role=role,
        name=payload.name or payload.email.split("@")[0],
        hospital_id=hospital_id,
        phone=payload.phone,
        theme=payload.theme or "light",
    )
    user_id = create_document("user", user_doc)

    # If hospital created, link admin user
    if hospital_id:
        db["hospital"].update_one({"_id": ObjectId(hospital_id)}, {"$set": {"admin_user_id": user_id}})

    access_token = create_access_token({"sub": user_id})
    return Token(access_token=access_token)


@app.post("/auth/login", response_model=Token)
def login(payload: LoginPayload):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=access_token)


@app.get("/me")
def me(current_user=Depends(get_current_user)):
    return current_user

# ------------------------------------
# Donors CRUD
# ------------------------------------
@app.get("/donors")
def list_donors(current_user=Depends(get_current_user)):
    # Hospitals and admins can view donors; donors can view self if linked
    filter_q: Dict[str, Any] = {}
    if current_user.get("role") in ["hospital", "bloodbank"]:
        filter_q["hospital_id"] = current_user.get("hospital_id")
    docs = db["donor"].find(filter_q).sort("created_at", -1)
    res = []
    for d in docs:
        d["_id"] = str(d["_id"])
        res.append(d)
    return res


@app.post("/donors")
def create_donor(donor: DonorSchema, current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    # Ensure hospital ownership
    if current_user.get("role") != "admin" and donor.hospital_id != current_user.get("hospital_id"):
        raise HTTPException(status_code=403, detail="Cannot create donor for another hospital")
    donor_id = create_document("donor", donor)
    return {"_id": donor_id}


@app.put("/donors/{donor_id}")
def update_donor(donor_id: str, donor: DonorSchema, current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    existing = db["donor"].find_one({"_id": ObjectId(donor_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Donor not found")
    if current_user.get("role") != "admin" and existing.get("hospital_id") != current_user.get("hospital_id"):
        raise HTTPException(status_code=403, detail="Not allowed")
    db["donor"].update_one({"_id": ObjectId(donor_id)}, {"$set": donor.model_dump() | {"updated_at": datetime.utcnow()}})
    return {"updated": True}


@app.delete("/donors/{donor_id}")
def delete_donor(donor_id: str, current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    existing = db["donor"].find_one({"_id": ObjectId(donor_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Donor not found")
    if current_user.get("role") != "admin" and existing.get("hospital_id") != current_user.get("hospital_id"):
        raise HTTPException(status_code=403, detail="Not allowed")
    db["donor"].delete_one({"_id": ObjectId(donor_id)})
    return {"deleted": True}

# ------------------------------------
# Inventory
# ------------------------------------
@app.get("/inventory")
def get_inventory(current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    hospital_id = current_user.get("hospital_id") if current_user.get("role") != "admin" else None
    q = {"hospital_id": hospital_id} if hospital_id else {}
    inv = db["inventory"].find_one(q)
    if not inv:
        # create a default inventory if hospital user and none exists
        if hospital_id:
            inv_id = create_document("inventory", InventorySchema(hospital_id=hospital_id))
            inv = db["inventory"].find_one({"_id": ObjectId(inv_id)})
        else:
            return []
    inv["_id"] = str(inv["_id"])
    return inv


@app.put("/inventory")
def update_inventory(payload: InventoryUpdatePayload, current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    hospital_id = current_user.get("hospital_id")
    inv = db["inventory"].find_one({"hospital_id": hospital_id})
    if not inv:
        inv_id = create_document("inventory", InventorySchema(hospital_id=hospital_id, units=payload.units))
        return {"_id": inv_id}
    db["inventory"].update_one({"_id": inv["_id"]}, {"$set": {"units": payload.units, "updated_at": datetime.utcnow()}})
    return {"updated": True}

# ------------------------------------
# Blood Requests & Alerts
# ------------------------------------
@app.post("/requests")
def create_request(req: BloodRequestSchema, current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    # ownership check
    if current_user.get("role") != "admin" and req.hospital_id != current_user.get("hospital_id"):
        raise HTTPException(status_code=403, detail="Cannot create request for another hospital")

    # find eligible donors by blood group and hospital
    donors = list(db["donor"].find({
        "hospital_id": req.hospital_id,
        "blood_group": req.blood_group,
        "is_eligible": True
    }))
    matched_ids = [str(d["_id"]) for d in donors]
    req_doc = req.model_dump()
    req_doc["matched_donor_ids"] = matched_ids
    request_id = create_document("bloodrequest", BloodRequestSchema(**req_doc))

    # Simulate notification sending - store notifications
    for d in donors:
        msg = f"Emergency request: {req.quantity} unit(s) of {req.blood_group} needed. Please contact hospital."
        notif = NotificationSchema(
            donor_id=str(d["_id"]),
            request_id=request_id,
            hospital_id=req.hospital_id,
            message=msg,
            channel="in-app",
            status="sent",
        )
        create_document("notification", notif)

    # Update request status if any alerts sent
    new_status = "alert_sent" if donors else "pending"
    db["bloodrequest"].update_one({"_id": ObjectId(request_id)}, {"$set": {"status": new_status}})

    return {"_id": request_id, "matched": len(donors), "status": new_status}


@app.get("/requests")
def list_requests(current_user=Depends(get_current_user)):
    q: Dict[str, Any] = {}
    if current_user.get("role") in ["hospital", "bloodbank"]:
        q["hospital_id"] = current_user.get("hospital_id")
    docs = db["bloodrequest"].find(q).sort("created_at", -1)
    res = []
    for r in docs:
        r["_id"] = str(r["_id"])
        res.append(r)
    return res


@app.put("/requests/{request_id}/status")
def update_request_status(request_id: str, payload: UpdateStatusPayload, current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    existing = db["bloodrequest"].find_one({"_id": ObjectId(request_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Request not found")
    if current_user.get("role") != "admin" and existing.get("hospital_id") != current_user.get("hospital_id"):
        raise HTTPException(status_code=403, detail="Not allowed")
    db["bloodrequest"].update_one({"_id": ObjectId(request_id)}, {"$set": {"status": payload.status, "updated_at": datetime.utcnow()}})
    return {"updated": True}

# ------------------------------------
# Donation completion -> update inventory + donor count + certificate
# ------------------------------------

def badge_for_count(count: int) -> str:
    if count >= 20:
        return "Gold"
    if count >= 10:
        return "Silver"
    if count >= 5:
        return "Bronze"
    return "Starter"


def ai_message(name: str, count: int, hospital: str) -> str:
    tier = badge_for_count(count)
    return (
        f"Dear {name}, your selfless act has made a real impact. "
        f"With {count} donation(s), you've earned the {tier} badge at {hospital}. "
        f"Thank you for keeping hope alive."
    )


@app.post("/donations/complete")
def complete_donation(payload: DonationCompletePayload, current_user=Depends(get_current_user)):
    require_role(current_user, ["hospital", "bloodbank", "admin"])
    donor = db["donor"].find_one({"_id": ObjectId(payload.donor_id)})
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    if current_user.get("role") != "admin" and donor.get("hospital_id") != current_user.get("hospital_id"):
        raise HTTPException(status_code=403, detail="Not allowed")

    # Record donation history
    donation = DonationSchema(
        hospital_id=payload.hospital_id,
        donor_id=payload.donor_id,
        date=date.today(),
        units=payload.units,
        notes=payload.notes,
    )
    create_document("donationhistory", donation)

    # Update donor
    new_count = (donor.get("donation_count") or 0) + 1
    db["donor"].update_one(
        {"_id": ObjectId(payload.donor_id)},
        {"$set": {"donation_count": new_count, "last_donation_date": date.today().isoformat(), "updated_at": datetime.utcnow()}}
    )

    # Update inventory (+units for donor blood group)
    inv = db["inventory"].find_one({"hospital_id": donor.get("hospital_id")})
    if not inv:
        inv_id = create_document("inventory", InventorySchema(hospital_id=donor.get("hospital_id")))
        inv = db["inventory"].find_one({"_id": ObjectId(inv_id)})
    units = inv.get("units", {})
    bg = donor.get("blood_group")
    units[bg] = int(units.get(bg, 0)) + int(payload.units)
    db["inventory"].update_one({"_id": inv["_id"]}, {"$set": {"units": units, "updated_at": datetime.utcnow()}})

    # Create certificate
    hospital = db["hospital"].find_one({"_id": ObjectId(donor.get("hospital_id"))}) if donor.get("hospital_id") else None
    cert = CertificateSchema(
        donor_id=payload.donor_id,
        hospital_id=donor.get("hospital_id"),
        donor_name=donor.get("name"),
        hospital_name=(hospital or {}).get("name", "Hospital"),
        donation_date=date.today(),
        donation_count=new_count,
        badge=badge_for_count(new_count),
        ai_message=ai_message(donor.get("name"), new_count, (hospital or {}).get("name", "Hospital"))
    )
    cert_id = create_document("certificate", cert)

    return {"ok": True, "donation_count": new_count, "certificate_id": cert_id}


@app.get("/certificates/{donor_id}")
def list_certificates(donor_id: str, current_user=Depends(get_current_user)):
    # hospital/admin can view; donor can view own if auth later extended
    docs = db["certificate"].find({"donor_id": donor_id}).sort("created_at", -1)
    res = []
    for c in docs:
        c["_id"] = str(c["_id"])
        res.append(c)
    return res

# ------------------------------------
# Notifications
# ------------------------------------
@app.get("/notifications")
def my_notifications(current_user=Depends(get_current_user)):
    # If logged in as donor in future, filter by donor_id matched to user
    role = current_user.get("role")
    q: Dict[str, Any] = {}
    if role in ["hospital", "bloodbank"]:
        q["hospital_id"] = current_user.get("hospital_id")
    docs = db["notification"].find(q).sort("created_at", -1)
    res = []
    for n in docs:
        n["_id"] = str(n["_id"])
        res.append(n)
    return res

# ------------------------------------
# Chatbot (Rule-based FAQ)
# ------------------------------------
class ChatPayload(BaseModel):
    message: str

FAQS = [
    ("eligibility", "You can usually donate if you are 18-65, >50kg, and feeling well. Wait 90 days between whole blood donations."),
    ("register", "Choose your role and sign up. Hospitals can include their blood bank details during registration."),
    ("inventory", "Inventory shows available units by blood group per hospital, updated after donations and issues."),
    ("emergency", "Create a blood request with group, quantity, urgency and patient notes. The system alerts matching donors automatically."),
]

@app.post("/chat")
def chat(payload: ChatPayload):
    msg = payload.message.lower().strip()
    for key, ans in FAQS:
        if key in msg:
            return {"reply": ans}
    if "how" in msg and "work" in msg:
        return {"reply": "HEMO LINK lets hospitals manage donors, inventory, and emergency requests with automated donor alerts and certificates."}
    return {"reply": "I can help with eligibility, register, inventory, or emergency steps. What would you like to know?"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
