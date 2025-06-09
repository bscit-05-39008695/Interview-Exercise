from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from functools import wraps
import os
import logging
import uuid
import jwt
from datetime import datetime, timedelta
from sqlalchemy import func, or_
from models import db, User, Provider

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create blueprint
provider_bp = Blueprint('providers', __name__, url_prefix='/api/providers')

# Configuration for file uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_token(user_id, role=None, expires_in_hours=24):
    """Generate JWT token for user"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=expires_in_hours),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    """Decode JWT token and return payload"""
    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}

def get_token_from_request():
    """Extract token from request headers"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    
    try:
        # Expected format: "Bearer <token>"
        token_type, token = auth_header.split(' ')
        if token_type.lower() != 'bearer':
            return None
        return token
    except ValueError:
        return None

def jwt_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authorization token required'}), 401
        
        payload = decode_token(token)
        if 'error' in payload:
            return jsonify({'error': payload['error']}), 401
        
        # Verify user exists
        user = User.find_by_id(payload['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        # Add user info to request context
        request.current_user = user
        request.token_payload = payload
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authorization token required'}), 401
        
        payload = decode_token(token)
        if 'error' in payload:
            return jsonify({'error': payload['error']}), 401
        
        user = User.find_by_id(payload['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        request.current_user = user
        request.token_payload = payload
        
        return f(*args, **kwargs)
    return decorated_function

def provider_required(f):
    """Decorator to require service provider role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authorization token required'}), 401
        
        payload = decode_token(token)
        if 'error' in payload:
            return jsonify({'error': payload['error']}), 401
        
        user = User.find_by_id(payload['user_id'])
        if not user or user.role not in ['service_provider', 'admin']:
            return jsonify({'error': 'Service provider access required'}), 403
        
        request.current_user = user
        request.token_payload = payload
        
        return f(*args, **kwargs)
    return decorated_function

@provider_bp.route('/auth/login', methods=['POST'])
def login():
    """Login user and return JWT token"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.find_by_email(email)
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate token
        token = generate_token(user.id, user.role)
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/auth/refresh', methods=['POST'])
@jwt_required
def refresh_token():
    """Refresh JWT token"""
    try:
        user = request.current_user
        new_token = generate_token(user.id, user.role)
        
        return jsonify({
            'message': 'Token refreshed successfully',
            'token': new_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/auth/verify', methods=['GET'])
@jwt_required
def verify_token():
    """Verify current token and return user info"""
    try:
        user = request.current_user
        
        return jsonify({
            'valid': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/register', methods=['POST'])
@jwt_required
def register_existing_user_as_provider():
    """Register an existing user as a service provider"""
    try:
        current_user = request.current_user
        
        # Check if user already has a provider profile
        if current_user.provider_profile:
            return jsonify({'error': 'User already has a provider profile'}), 409
        
        # Get form data
        data = request.form.to_dict()
        files = request.files
        
        # Validate required fields
        required_fields = ['businessName', 'serviceCategory', 'serviceDescription', 'experienceYears', 'ratePerHour']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate numeric fields
        try:
            experience_years = int(data['experienceYears'])
            rate_per_hour = float(data['ratePerHour'])
            if experience_years < 0:
                return jsonify({'error': 'Experience years must be non-negative'}), 400
            if rate_per_hour <= 0:
                return jsonify({'error': 'Hourly rate must be greater than 0'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid numeric values for experience or rate'}), 400
        
        # Handle file uploads
        uploaded_files = {}
        required_documents = ['identificationDoc', 'certifications', 'insuranceProof']
        
        for doc_field in required_documents:
            if doc_field not in files or not files[doc_field].filename:
                return jsonify({'error': f'{doc_field} is required'}), 400
            
            file = files[doc_field]
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                file.save(file_path)
                uploaded_files[doc_field] = file_path
            else:
                return jsonify({'error': f'Invalid file format for {doc_field}'}), 400
        
        # Create provider profile
        provider = Provider(
            user_id=current_user.id,
            business_name=data['businessName'],
            service_category=data['serviceCategory'],
            service_description=data['serviceDescription'],
            experience_years=experience_years,
            rate_per_hour=rate_per_hour,
            identification_doc=uploaded_files['identificationDoc'],
            certifications=uploaded_files['certifications'],
            insurance_proof=uploaded_files['insuranceProof']
        )
        
        db.session.add(provider)
        
        # Update user role to service_provider
        current_user.role = 'service_provider'
        
        db.session.commit()
        
        # Generate new token with updated role
        new_token = generate_token(current_user.id, current_user.role)
        
        return jsonify({
            'message': 'Provider registration submitted successfully',
            'provider': provider.to_dict(),
            'token': new_token  # Return new token with updated role
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
