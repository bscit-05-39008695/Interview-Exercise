from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), default='client', nullable=False)  # client, service_provider, admin
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Fixed relationship - specify which foreign key to use
    provider_profile = db.relationship(
        'Provider', 
        foreign_keys='Provider.user_id',
        backref='user', 
        uselist=False, 
        cascade='all, delete-orphan'
    )
    
    # Separate relationship for approvals
    approved_providers = db.relationship(
        'Provider',
        foreign_keys='Provider.approved_by',
        backref='approver'
    )
    
    def __init__(self, first_name, last_name, email, password, phone_number, address, role='client', username=None):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password  # This will use the setter
        self.phone_number = phone_number
        self.address = address
        self.role = role
        self.username = username
    
    @property
    def password(self):
        raise AttributeError('Password is not readable')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def save(self):
        db.session.add(self)
        db.session.commit()
        return self
    
    @staticmethod
    def find_by_email(email):
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def find_by_id(user_id):
        return User.query.get(user_id)
    
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_password(password):
        return len(password) >= 6
    
    @staticmethod
    def validate_phone(phone):
        # Basic phone validation - adjust pattern as needed
        pattern = r'^\+?1?-?\.?\s?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$'
        return re.match(pattern, phone) is not None or len(phone.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')) >= 10
    
    def to_dict(self):
        return {
            'id': self.id,
            'firstName': self.first_name,
            'lastName': self.last_name,
            'username': self.username,
            'email': self.email,
            'phoneNumber': self.phone_number,
            'address': self.address,
            'role': self.role,
            'isActive': self.is_active,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'updatedAt': self.updated_at.isoformat() if self.updated_at else None
        }


class Provider(db.Model):
    __tablename__ = 'providers'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    business_name = db.Column(db.String(100), nullable=False)
    service_category = db.Column(db.String(50), nullable=False)
    service_description = db.Column(db.Text, nullable=False)
    experience_years = db.Column(db.Integer, nullable=False)
    rate_per_hour = db.Column(db.Float, nullable=False)
    
    # Document paths
    identification_doc = db.Column(db.String(255), nullable=False)
    certifications = db.Column(db.String(255), nullable=False)
    insurance_proof = db.Column(db.String(255), nullable=False)
    
    # Status and approval
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, approved, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    
    # ADD THIS LINE - Availability status
    is_available = db.Column(db.Boolean, default=True, nullable=False)
    
    # Ratings and reviews
    average_rating = db.Column(db.Float, default=0.0)
    total_reviews = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships - removed from here since they're now defined in User model
    services = db.relationship('ProviderService', backref='provider', cascade='all, delete-orphan')
    
    def approve(self, approved_by_user_id):
        self.status = 'approved'
        self.approved_by = approved_by_user_id
        self.approved_at = datetime.utcnow()
        db.session.commit()
    
    def reject(self, rejected_by_user_id, reason):
        self.status = 'rejected'
        self.approved_by = rejected_by_user_id
        self.rejection_reason = reason
        self.approved_at = datetime.utcnow()
        db.session.commit()
    
    # ADD THIS METHOD - Toggle availability
    def set_availability(self, is_available):
        self.is_available = is_available
        db.session.commit()
    
    @staticmethod
    def get_approved_providers():
        return Provider.query.filter_by(status='approved').all()
    
    @staticmethod
    def get_pending_providers():
        return Provider.query.filter_by(status='pending').all()
    
    # ADD THIS METHOD - Get available providers
    @staticmethod
    def get_available_providers():
        return Provider.query.filter_by(status='approved', is_available=True).all()
    
    @staticmethod
    def search_by_category(category):
        return Provider.query.filter_by(status='approved', service_category=category).all()
    
    def to_dict(self):
        return {
            'id': self.id,
            'userId': self.user_id,
            'businessName': self.business_name,
            'serviceCategory': self.service_category,
            'serviceDescription': self.service_description,
            'experienceYears': self.experience_years,
            'ratePerHour': self.rate_per_hour,
            'status': self.status,
            'approvedBy': self.approved_by,
            'approvedAt': self.approved_at.isoformat() if self.approved_at else None,
            'rejectionReason': self.rejection_reason,
            'isAvailable': self.is_available,  # ADD THIS LINE
            'averageRating': self.average_rating,
            'totalReviews': self.total_reviews,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'updatedAt': self.updated_at.isoformat() if self.updated_at else None,
            'user': self.user.to_dict() if self.user else None
        }

class ProviderService(db.Model):
    __tablename__ = 'provider_services'
    
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('providers.id'), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    service_description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'providerId': self.provider_id,
            'serviceName': self.service_name,
            'serviceDescription': self.service_description,
            'price': self.price,
            'durationMinutes': self.duration_minutes,
            'isActive': self.is_active,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'updatedAt': self.updated_at.isoformat() if self.updated_at else None
        }