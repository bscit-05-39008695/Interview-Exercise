from marshmallow import Schema, fields, validate, ValidationError, pre_load
import re

# Custom validators
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValidationError('Invalid email format')

def validate_password(password):
    if len(password) < 6:
        raise ValidationError('Password must be at least 6 characters long')

def validate_phone(phone):
    # Remove common phone formatting characters
    cleaned = phone.replace('-', '').replace(' ', '').replace('(', '').replace(')', '').replace('+', '')
    if not cleaned.isdigit() or len(cleaned) < 10:
        raise ValidationError('Invalid phone number format')

def validate_positive_number(value):
    if value <= 0:
        raise ValidationError('Value must be greater than 0')

def validate_non_negative_integer(value):
    if value < 0:
        raise ValidationError('Value must be non-negative')

# User Schemas
class UserRegistrationSchema(Schema):
    firstName = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    lastName = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    username = fields.Str(required=False, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True, validate=validate_email)
    password = fields.Str(required=True, validate=validate_password)
    phoneNumber = fields.Str(required=True, validate=validate_phone)
    address = fields.Str(required=True, validate=validate.Length(min=1))
    role = fields.Str(required=False, validate=validate.OneOf(['client', 'service_provider', 'admin']), missing='client')

class UserLoginSchema(Schema):
    email = fields.Email(required=True, validate=validate_email)
    password = fields.Str(required=True, validate=validate.Length(min=1))

class UserResponseSchema(Schema):
    id = fields.Int()
    firstName = fields.Str()
    lastName = fields.Str()
    username = fields.Str()
    email = fields.Email()
    phoneNumber = fields.Str()
    address = fields.Str()
    role = fields.Str()
    isActive = fields.Bool()
    createdAt = fields.DateTime()
    updatedAt = fields.DateTime()

# Provider Schemas
class ProviderRegistrationSchema(Schema):
    # Personal Information (for new user registration)
    firstName = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    lastName = fields.Str(required=True, validate=validate.Length(min=1, max=50))  
    username = fields.Str(required=False, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True, validate=validate_email)
    password = fields.Str(required=True, validate=validate_password)
    passwordConfirm = fields.Str(required=True)
    phoneNumber = fields.Str(required=True, validate=validate_phone)
    address = fields.Str(required=True, validate=validate.Length(min=1))
    
    # Business Information
    businessName = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    serviceCategory = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    serviceDescription = fields.Str(required=True, validate=validate.Length(min=1))
    experienceYears = fields.Int(required=True, validate=validate_non_negative_integer)
    ratePerHour = fields.Float(required=True, validate=validate_positive_number)
    
    @pre_load
    def validate_password_confirmation(self, data, **kwargs):
        if data.get('password') != data.get('passwordConfirm'):
            raise ValidationError('Passwords do not match', field_name='passwordConfirm')
        return data

class ExistingUserProviderRegistrationSchema(Schema):
    # Business Information only (for existing users)
    businessName = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    serviceCategory = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    serviceDescription = fields.Str(required=True, validate=validate.Length(min=1))
    experienceYears = fields.Int(required=True, validate=validate_non_negative_integer)
    ratePerHour = fields.Float(required=True, validate=validate_positive_number)

class ProviderResponseSchema(Schema):
    id = fields.Int()
    userId = fields.Int()
    businessName = fields.Str()
    serviceCategory = fields.Str()
    serviceDescription = fields.Str()
    experienceYears = fields.Int()
    ratePerHour = fields.Float()
    status = fields.Str()
    approvedBy = fields.Int()
    approvedAt = fields.DateTime()
    rejectionReason = fields.Str()
    averageRating = fields.Float()
    totalReviews = fields.Int()
    createdAt = fields.DateTime()
    updatedAt = fields.DateTime()
    user = fields.Nested(UserResponseSchema)

class ProviderApprovalSchema(Schema):
    status = fields.Str(validate=validate.OneOf(['approved', 'rejected']))

class ProviderRejectionSchema(Schema):
    reason = fields.Str(required=True, validate=validate.Length(min=1))

# Provider Service Schemas
class ProviderServiceSchema(Schema):
    serviceName = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    serviceDescription = fields.Str(required=False)
    price = fields.Float(required=True, validate=validate_positive_number)
    durationMinutes = fields.Int(required=False, validate=validate.Range(min=1))
    isActive = fields.Bool(missing=True)

class ProviderServiceResponseSchema(Schema):
    id = fields.Int()
    providerId = fields.Int()
    serviceName = fields.Str()
    serviceDescription = fields.Str()
    price = fields.Float()
    durationMinutes = fields.Int()
    isActive = fields.Bool()
    createdAt = fields.DateTime()
    updatedAt = fields.DateTime()

# Search and Filter Schemas
class ProviderSearchSchema(Schema):
    category = fields.Str(required=False)
    minRating = fields.Float(required=False, validate=validate.Range(min=0, max=5))
    maxRate = fields.Float(required=False, validate=validate_positive_number)
    minRate = fields.Float(required=False, validate=validate_positive_number)
    location = fields.Str(required=False)

# Response Schemas for API endpoints
class MessageResponseSchema(Schema):
    message = fields.Str()

class ErrorResponseSchema(Schema):
    error = fields.Str()

class UserRegistrationResponseSchema(Schema):
    message = fields.Str()
    user = fields.Nested(UserResponseSchema)

class ProviderRegistrationResponseSchema(Schema):
    message = fields.Str()
    user = fields.Nested(UserResponseSchema)
    provider = fields.Nested(ProviderResponseSchema)

class LoginResponseSchema(Schema):
    message = fields.Str()
    user = fields.Nested(UserResponseSchema)

class ProvidersListResponseSchema(Schema):
    providers = fields.List(fields.Nested(ProviderResponseSchema))

class UserMeResponseSchema(Schema):
    user = fields.Nested(UserResponseSchema)