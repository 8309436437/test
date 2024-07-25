# models.py
from beanie import Document
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class Booking(Document):
    user_id: str
    booking_time: datetime
    description: str

    class Settings:
        name = "bookings"

    class Config:
        schema_extra = {
            "example": {
                "user_id": "user@example.com",
                "booking_time": "2023-07-25T15:00:00Z",
                "description": "A brief description of the booking."
            }
        }

class BookingCreate(BaseModel):
    booking_time: datetime
    description: str

