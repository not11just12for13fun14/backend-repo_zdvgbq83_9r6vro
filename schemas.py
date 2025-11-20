"""
Database Schemas for HEMO LINK

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
Use these for validation and to keep a consistent structure.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict
from datetime import date, datetime

# Core Users and Auth
class User(BaseModel):
    email: EmailStr = Field(..., description="Login email (unique)")
    password_hash: str = Field(..., description="BCrypt hashed password")
    role: str = Field(..., description="One of: admin, hospital, bloodbank, donor")
    name: Optional[str] = Field(None, description="Display name")
    hospital_id: Optional[str] = Field(None, description="Linked hospital _id for hospital/bloodbank staff")
    phone: Optional[str] = None
    theme: Optional[str] = Field("light", description="light | dark")
    is_active: bool = Field(True)

class Hospital(BaseModel):
    name: str
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    pincode: Optional[str] = None
    contact_numbers: List[str] = Field(default_factory=list)
    blood_bank_details: Optional[str] = None
    admin_user_id: Optional[str] = Field(None, description="_id of the hospital admin user")

# Donors and Donations
class Donor(BaseModel):
    hospital_id: str = Field(..., description="Owning hospital _id")
    name: str
    blood_group: str = Field(..., pattern="^(A|B|AB|O)[+-]$")
    phone: str
    location: Optional[str] = None
    last_donation_date: Optional[date] = None
    donation_count: int = 0
    is_eligible: bool = True
    notes: Optional[str] = None

class DonationHistory(BaseModel):
    hospital_id: str
    donor_id: str
    date: date
    units: float = Field(ge=0.1)
    notes: Optional[str] = None

# Inventory (per hospital)
class Inventory(BaseModel):
    hospital_id: str
    units: Dict[str, int] = Field(
        default_factory=lambda: {
            "A+": 0, "A-": 0, "B+": 0, "B-": 0, "AB+": 0, "AB-": 0, "O+": 0, "O-": 0
        }
    )
    low_threshold: int = 5
    critical_threshold: int = 2

# Requests and Notifications
class BloodRequest(BaseModel):
    hospital_id: str
    blood_group: str = Field(..., pattern="^(A|B|AB|O)[+-]$")
    quantity: int = Field(..., ge=1)
    urgency: str = Field(..., description="low|medium|high|critical")
    patient_name: Optional[str] = None
    patient_details: Optional[str] = None
    status: str = Field("pending", description="pending|alert_sent|fulfilled|rejected")
    matched_donor_ids: List[str] = Field(default_factory=list)

class Notification(BaseModel):
    donor_id: str
    request_id: str
    hospital_id: str
    message: str
    channel: str = Field("in-app")
    status: str = Field("sent")

# Certificates
class Certificate(BaseModel):
    donor_id: str
    hospital_id: str
    donor_name: str
    hospital_name: str
    donation_date: date
    donation_count: int
    badge: str
    ai_message: str

"""
Note: The app will use these schemas for validation alongside helper functions
from database.py (create_document, get_documents). Collections will be named as
lowercase class names (e.g., User -> "user").
"""
