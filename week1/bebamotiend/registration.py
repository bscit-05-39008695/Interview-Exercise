from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename
from functools import wraps
import os
import logging
import uuid
from datetime import datetime, timedelta
from sqlalchemy import func, or_
from models import db, User, Provider, ProviderService

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create blueprints
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
user_bp = Blueprint('users', __name__, url_prefix='/api/users')
provider_bp = Blueprint('providers', __name__, url_prefix='/api/providers')

# Configuration for file uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== DECORATORS =====

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = User.find_by_id(session['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def provider_required(f):
    """Decorator to require service provider role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = User.find_by_id(session['user_id'])
        if not user or user.role != 'service_provider':
            return jsonify({'error': 'Service provider access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ===== AUTHENTICATION ROUTES =====

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'password', 'phoneNumber', 'address']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate input
        if not User.validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if not User.validate_password(data['password']):
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        if not User.validate_phone(data['phoneNumber']):
            return jsonify({'error': 'Invalid phone number format'}), 400
        
        # Check if user already exists
        if User.find_by_email(data['email']):
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create new user
        user = User(
            first_name=data['firstName'],
            last_name=data['lastName'],
            email=data['email'],
            password=data['password'],
            phone_number=data['phoneNumber'],
            address=data['address'],
            role=data.get('role', 'client'),
            username=data.get('username')
        )
        
        user.save()
        
        # Set session
        session['user_id'] = user.id
        session['user_role'] = user.role
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/register-provider', methods=['POST'])
def register_provider():
    """Register a new user as a service provider"""
    try:
        # Get form data (multipart/form-data due to file uploads)
        data = request.form.to_dict()
        files = request.files
        
        # Validate required personal information fields
        required_personal_fields = ['firstName', 'lastName', 'email', 'password', 'passwordConfirm', 'phoneNumber', 'address']
        for field in required_personal_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate password confirmation
        if data['password'] != data['passwordConfirm']:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Validate input
        if not User.validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if not User.validate_password(data['password']):
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        if not User.validate_phone(data['phoneNumber']):
            return jsonify({'error': 'Invalid phone number format'}), 400
        
        # Check if user already exists
        if User.find_by_email(data['email']):
            return jsonify({'error': 'Email already registered'}), 409
        
        # Validate required business information fields
        required_business_fields = ['businessName', 'serviceCategory', 'serviceDescription', 'experienceYears', 'ratePerHour']
        for field in required_business_fields:
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
                
                # Ensure upload directory exists
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                
                file.save(file_path)
                uploaded_files[doc_field] = file_path
            else:
                return jsonify({'error': f'Invalid file format for {doc_field}'}), 400
        
        # Create new user with service_provider role
        user = User(
            first_name=data['firstName'],
            last_name=data['lastName'],
            email=data['email'],
            password=data['password'],
            phone_number=data['phoneNumber'],
            address=data['address'],
            role='service_provider',
            username=data.get('username')
        )
        
        user.save()
        
        # Create provider profile
        provider = Provider(
            user_id=user.id,
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
        db.session.commit()
        
        # Set session
        session['user_id'] = user.id
        session['user_role'] = user.role
        
        return jsonify({
            'message': 'Provider registration submitted successfully. Your application is pending approval.',
            'user': user.to_dict(),
            'provider': provider.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.find_by_email(email)
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Set session
        session['user_id'] = user.id
        session['user_role'] = user.role
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout user"""
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200

@auth_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user information"""
    try:
        user = User.find_by_id(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== USER MANAGEMENT ROUTES =====

@user_bp.route('/', methods=['GET'])
@admin_required
def get_all_users():
    """Get all users (admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        role_filter = request.args.get('role')
        search = request.args.get('search')
        
        # Start with base query
        query = User.query
        
        # Apply filters
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                or_(
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern),
                    User.email.ilike(search_pattern)
                )
            )
        
        # Order by creation date (newest first)
        query = query.order_by(User.created_at.desc())
        
        # Paginate results
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        return jsonify({
            'users': [user.to_dict() for user in pagination.items],
            'pagination': {
                'page': page,
                'pages': pagination.pages,
                'per_page': per_page,
                'total': pagination.total,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/<int:user_id>', methods=['GET'])
@login_required
def get_user_by_id(user_id):
    """Get user by ID (admin can see any user, regular users can only see themselves)"""
    try:
        current_user = User.find_by_id(session['user_id'])
        
        # Check permissions
        if current_user.role != 'admin' and session['user_id'] != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update user information"""
    try:
        current_user = User.find_by_id(session['user_id'])
        
        # Check permissions
        if current_user.role != 'admin' and session['user_id'] != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Fields that can be updated
        updatable_fields = ['first_name', 'last_name', 'phone_number', 'address', 'username']
        
        # Only admins can update role and active status
        if current_user.role == 'admin':
            updatable_fields.extend(['role', 'is_active'])
        
        # Update fields
        for field in updatable_fields:
            if field in data:
                if field == 'phone_number' and data[field]:
                    if not User.validate_phone(data[field]):
                        return jsonify({'error': 'Invalid phone number format'}), 400
                
                setattr(user, field, data[field])
        
        # Handle email update separately
        if 'email' in data and data['email'] != user.email:
            if not User.validate_email(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            
            # Check if email is already taken
            existing_user = User.find_by_email(data['email'])
            if existing_user and existing_user.id != user.id:
                return jsonify({'error': 'Email already taken'}), 409
            
            user.email = data['email']
        
        # Handle password update
        if 'password' in data:
            if not User.validate_password(data['password']):
                return jsonify({'error': 'Password must be at least 6 characters long'}), 400
            user.set_password(data['password'])
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/<int:user_id>/deactivate', methods=['POST'])
@admin_required
def deactivate_user(user_id):
    """Deactivate a user account (admin only)"""
    try:
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_active = False
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User deactivated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/<int:user_id>/activate', methods=['POST'])
@admin_required
def activate_user(user_id):
    """Activate a user account (admin only)"""
    try:
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_active = True
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User activated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/stats', methods=['GET'])
@admin_required
def get_user_stats():
    """Get user statistics (admin only)"""
    try:
        total_users = User.query.count()
        active_users = User.query.filter(User.is_active == True).count()
        inactive_users = total_users - active_users
        
        # Count by role
        clients = User.query.filter(User.role == 'client').count()
        providers = User.query.filter(User.role == 'service_provider').count()
        admins = User.query.filter(User.role == 'admin').count()
        
        # Recent registrations (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_registrations = User.query.filter(User.created_at >= thirty_days_ago).count()
        
        return jsonify({
            'stats': {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': inactive_users,
                'clients': clients,
                'service_providers': providers,
                'admins': admins,
                'recent_registrations': recent_registrations
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/search', methods=['GET'])
@admin_required
def search_users():
    """Search users by various criteria (admin only)"""
    try:
        query_param = request.args.get('q', '').strip()
        role_filter = request.args.get('role')
        active_filter = request.args.get('active')
        
        if not query_param:
            return jsonify({'error': 'Search query is required'}), 400
        
        # Start with base query
        query = User.query
        
        # Apply search across multiple fields
        search_pattern = f"%{query_param}%"
        query = query.filter(
            or_(
                User.first_name.ilike(search_pattern),
                User.last_name.ilike(search_pattern),
                User.email.ilike(search_pattern),
                User.username.ilike(search_pattern)
            )
        )
        
        # Apply additional filters
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        if active_filter is not None:
            is_active = active_filter.lower() == 'true'
            query = query.filter(User.is_active == is_active)
        
        users = query.limit(50).all()  # Limit results
        
        return jsonify({
            'users': [user.to_dict() for user in users],
            'count': len(users)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== PROVIDER ROUTES =====

@provider_bp.route('/register', methods=['POST'])
@login_required
def register_existing_user_as_provider():
    """Register an existing user as a service provider"""
    try:
        current_user = User.find_by_id(session['user_id'])
        
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
        session['user_role'] = 'service_provider'
        
        db.session.commit()
        
        return jsonify({
            'message': 'Provider registration submitted successfully',
            'provider': provider.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/search', methods=['GET'])
def search_providers():
    """Search providers by various criteria"""
    try:
        # Get search parameters
        query_text = request.args.get('q', '').strip()
        service_type = request.args.get('service_type')
        category = request.args.get('category')
        location = request.args.get('location')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Start with approved providers
        query = Provider.query.filter(Provider.status == 'approved')
        
        # Text search
        if query_text:
            search_pattern = f"%{query_text}%"
            query = query.join(User).filter(
                or_(
                    Provider.business_name.ilike(search_pattern),
                    Provider.service_description.ilike(search_pattern),
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern)
                )
            )
        
        # Category filter
        if category:
            query = query.filter(Provider.service_category == category)
        
        # Service type filter (if you have a services field)
        if service_type and hasattr(Provider, 'services'):
            query = query.filter(Provider.services.contains(service_type))
        
        # Location filter
        if location:
            query = query.join(User).filter(User.address.ilike(f"%{location}%"))
        
        # Order by creation date
        query = query.order_by(Provider.created_at.desc())
        
        # Paginate results
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        return jsonify({
            'providers': [provider.to_dict() for provider in pagination.items],
            'pagination': {
                'page': page,
                'pages': pagination.pages,
                'per_page': per_page,
                'total': pagination.total,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@provider_bp.route('/nearby', methods=['GET'])
def get_nearby_providers():
    """Get providers near a specific location"""
    try:
        logger.info("Starting get_nearby_providers request")
        
        # Get parameters
        lat = request.args.get('lat', type=float)
        lng = request.args.get('lng', type=float)
        service_type = request.args.get('type', 'towing')
        radius = request.args.get('radius', 10, type=int)
        
        logger.info(f"Parameters: lat={lat}, lng={lng}, service_type={service_type}, radius={radius}")
        
        if lat is None or lng is None:
            logger.error("Missing latitude or longitude")
            return jsonify({'error': 'Latitude and longitude are required'}), 400
        
        # Valid service types
        valid_service_types = ['towing', 'battery', 'tire', 'fuel', 'lockout']
        if service_type not in valid_service_types:
            logger.error(f"Invalid service type: {service_type}")
            return jsonify({'error': f'Invalid service type. Must be one of: {valid_service_types}'}), 400
        
        try:
            logger.info("Attempting database query...")
            
            # Query only approved providers (remove is_available filter for now)
            providers = Provider.query.filter(
                Provider.status == 'approved'
            ).limit(20).all()
            
            logger.info(f"Found {len(providers)} providers")
            
        except Exception as db_error:
            logger.error(f"Database query error: {str(db_error)}")
            return jsonify({
                'error': 'Database connection failed',
                'details': str(db_error)
            }), 500
        
        providers_data = []
        for provider in providers:
            try:
                # Get basic provider data
                provider_dict = provider.to_dict()
                
                # Add roadside assistance specific data
                provider_dict['distance'] = round(2.5 + (provider.id % 8), 1)  # Mock distance 2.5-10km
                provider_dict['rating'] = round(4.0 + (provider.id % 11) / 10, 1)  # Mock rating 4.0-5.0
                provider_dict['reviews_count'] = 15 + (provider.id % 35)  # Mock review count
                provider_dict['response_time'] = f"{10 + (provider.id % 20)} mins"  # Mock response time
                provider_dict['is_available'] = True  # Mock availability since column doesn't exist yet
                
                # Add service offerings and pricing
                provider_dict['services'] = valid_service_types
                provider_dict['pricing'] = {
                    'towing': 3000 + (provider.id % 5) * 500,  # 3000-5000 KES
                    'battery': 600 + (provider.id % 4) * 100,   # 600-900 KES
                    'tire': 1000 + (provider.id % 3) * 200,    # 1000-1400 KES
                    'fuel': 500 + (provider.id % 3) * 100,     # 500-700 KES
                    'lockout': 800 + (provider.id % 4) * 100   # 800-1100 KES
                }
                
                # Add mock location near user (you'll need to add actual coordinates to your model)
                provider_dict['latitude'] = lat + ((provider.id % 10 - 5) * 0.01)  # Within ~1km
                provider_dict['longitude'] = lng + ((provider.id % 10 - 5) * 0.01)
                
                # Add additional useful info
                provider_dict['vehicle_type'] = ['Tow Truck', 'Service Van', 'Mobile Unit'][provider.id % 3]
                provider_dict['equipment'] = ['Basic Tools', 'Advanced Equipment', 'Professional Grade'][provider.id % 3]
                
                providers_data.append(provider_dict)
                
            except Exception as provider_error:
                logger.error(f"Error processing provider {provider.id}: {str(provider_error)}")
                continue
        
        logger.info(f"Successfully processed {len(providers_data)} providers")
        
        return jsonify({
            'providers': providers_data,
            'count': len(providers_data),
            'search_params': {
                'latitude': lat,
                'longitude': lng,
                'service_type': service_type,
                'radius': radius
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Unexpected error in get_nearby_providers: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'error': 'Internal server error',
            'details': str(e)
        }), 500
@provider_bp.route('/pending', methods=['GET'])
@admin_required
def get_pending_providers():
    """Get all pending provider applications (admin only)"""
    try:
        providers = Provider.query.filter(Provider.status == 'pending').all()
        
        return jsonify({
            'providers': [provider.to_dict() for provider in providers]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/<int:provider_id>/approve', methods=['POST'])
@admin_required
def approve_provider(provider_id):
    """Approve a provider application (admin only)"""
    try:
        provider = Provider.query.get(provider_id)
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        if provider.status != 'pending':
            return jsonify({'error': 'Provider application is not pending'}), 400
        
        provider.approve(session['user_id'])
        
        return jsonify({
            'message': 'Provider approved successfully',
            'provider': provider.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/<int:provider_id>/reject', methods=['POST'])
@admin_required
def reject_provider(provider_id):
    """Reject a provider application (admin only)"""
    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided')
        
        provider = Provider.query.get(provider_id)
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        if provider.status != 'pending':
            return jsonify({'error': 'Provider application is not pending'}), 400
        
        provider.reject(session['user_id'], reason)
        
        return jsonify({
            'message': 'Provider rejected successfully',
            'provider': provider.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@provider_bp.route('/my-profile', methods=['PUT'])
@provider_required
def update_my_provider_profile():
    """Update current user's provider profile"""
    try:
        provider = Provider.query.filter_by(user_id=session['user_id']).first()
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        # Get form data
        data = request.form.to_dict()
        files = request.files
        
        # Update basic information
        updatable_fields = ['business_name', 'service_category', 'service_description', 'experience_years', 'rate_per_hour']
        
        for field in updatable_fields:
            if field in data:
                if field in ['experience_years', 'rate_per_hour']:
                    try:
                        value = int(data[field]) if field == 'experience_years' else float(data[field])
                        if value < 0:
                            return jsonify({'error': f'{field} must be non-negative'}), 400
                        setattr(provider, field, value)
                    except (ValueError, TypeError):
                        return jsonify({'error': f'Invalid value for {field}'}), 400
                else:
                    setattr(provider, field, data[field])
        
        # Handle file uploads if provided
        document_fields = ['identification_doc', 'certifications', 'insurance_proof']
        for doc_field in document_fields:
            if doc_field in files and files[doc_field].filename:
                file = files[doc_field]
                if file and allowed_file(file.filename):
                    # Delete old file if exists
                    old_file_path = getattr(provider, doc_field)
                    if old_file_path and os.path.exists(old_file_path):
                        os.remove(old_file_path)
                    
                    # Save new file
                    filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                    file.save(file_path)
                    setattr(provider, doc_field, file_path)
                else:
                    return jsonify({'error': f'Invalid file format for {doc_field}'}), 400
        
        provider.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Provider profile updated successfully',
            'provider': provider.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/my-profile/availability', methods=['PUT'])
@provider_required
def update_availability():
    """Update provider availability status"""
    try:
        provider = Provider.query.filter_by(user_id=session['user_id']).first()
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        data = request.get_json()
        is_available = data.get('is_available')
        
        if is_available is None:
            return jsonify({'error': 'is_available field is required'}), 400
        
        provider.is_available = bool(is_available)
        provider.updated_at = datetime.utcnow()
        db.session.commit()
        
        status = 'available' if provider.is_available else 'unavailable'
        return jsonify({
            'message': f'Provider status updated to {status}',
            'provider': provider.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/categories', methods=['GET'])
def get_service_categories():
    """Get all available service categories"""
    try:
        # Get distinct categories from approved providers
        categories = db.session.query(Provider.service_category).filter(
            Provider.status == 'approved'
        ).distinct().all()
        
        category_list = [cat[0] for cat in categories if cat[0]]
        
        # Add default categories if none exist
        if not category_list:
            category_list = [
                'Towing Services',
                'Battery Services',
                'Tire Services',
                'Fuel Delivery',
                'Lockout Services',
                'General Roadside Assistance'
            ]
        
        return jsonify({
            'categories': sorted(category_list)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/stats', methods=['GET'])
@admin_required
def get_provider_stats():
    """Get provider statistics (admin only)"""
    try:
        total_providers = Provider.query.count()
        approved_providers = Provider.query.filter(Provider.status == 'approved').count()
        pending_providers = Provider.query.filter(Provider.status == 'pending').count()
        rejected_providers = Provider.query.filter(Provider.status == 'rejected').count()
        available_providers = Provider.query.filter(
            Provider.status == 'approved',
            Provider.is_available == True
        ).count()
        
        # Recent applications (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_applications = Provider.query.filter(Provider.created_at >= thirty_days_ago).count()
        
        # Category breakdown
        category_stats = db.session.query(
            Provider.service_category,
            func.count(Provider.id).label('count')
        ).filter(Provider.status == 'approved').group_by(Provider.service_category).all()
        
        category_breakdown = {cat: count for cat, count in category_stats}
        
        return jsonify({
            'stats': {
                'total_providers': total_providers,
                'approved_providers': approved_providers,
                'pending_providers': pending_providers,
                'rejected_providers': rejected_providers,
                'available_providers': available_providers,
                'recent_applications': recent_applications,
                'category_breakdown': category_breakdown
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/dashboard', methods=['GET'])
@provider_required
def get_provider_dashboard():
    """Get provider dashboard data"""
    try:
        provider = Provider.query.filter_by(user_id=session['user_id']).first()
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        # Mock dashboard data - replace with actual calculations
        dashboard_data = {
            'profile_status': provider.status,
            'is_available': provider.is_available,
            'total_requests': 0,  # Count from requests table
            'completed_requests': 0,  # Count completed requests
            'pending_requests': 0,  # Count pending requests
            'total_earnings': 0.0,  # Sum of earnings
            'rating': 4.5,  # Average rating
            'recent_requests': [],  # Last 5 requests
            'monthly_stats': {
                'requests': 0,
                'earnings': 0.0,
                'rating': 4.5
            }
        }
        
        return jsonify({
            'dashboard': dashboard_data,
            'provider': provider.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== SERVICE MANAGEMENT ROUTES =====

@provider_bp.route('/services', methods=['GET'])
@provider_required
def get_provider_services():
    """Get services offered by the provider"""
    try:
        provider = Provider.query.filter_by(user_id=session['user_id']).first()
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        # Get provider's services
        services = ProviderService.query.filter_by(provider_id=provider.id).all()
        
        return jsonify({
            'services': [service.to_dict() for service in services]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/services', methods=['POST'])
@provider_required
def add_provider_service():
    """Add a new service"""
    try:
        provider = Provider.query.filter_by(user_id=session['user_id']).first()
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['service_name', 'description', 'price']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate price
        try:
            price = float(data['price'])
            if price <= 0:
                return jsonify({'error': 'Price must be greater than 0'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid price format'}), 400
        
        # Create new service
        service = ProviderService(
            provider_id=provider.id,
            service_name=data['service_name'],
            description=data['description'],
            price=price,
            is_active=data.get('is_active', True)
        )
        
        db.session.add(service)
        db.session.commit()
        
        return jsonify({
            'message': 'Service added successfully',
            'service': service.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@provider_bp.route('/services/<int:service_id>', methods=['PUT'])
@provider_required
def update_provider_service(service_id):
    """Update a service"""
    try:
        provider = Provider.query.filter_by(user_id=session['user_id']).first()
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        service = ProviderService.query.filter_by(
            id=service_id,
            provider_id=provider.id
        ).first()
        
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        data = request.get_json()
        
        # Update fields
        updatable_fields = ['service_name', 'description', 'price', 'is_active']
        for field in updatable_fields:
            if field in data:
                if field == 'price':
                    try:
                        price = float(data[field])
                        if price <= 0:
                            return jsonify({'error': 'Price must be greater than 0'}), 400
                        service.price = price
                    except (ValueError, TypeError):
                        return jsonify({'error': 'Invalid price format'}), 400
                else:
                    setattr(service, field, data[field])
        
        service.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Service updated successfully',
            'service': service.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@provider_bp.route('/services/<int:service_id>', methods=['DELETE'])
@provider_required
def delete_provider_service(service_id):
    """Delete a service"""
    try:
        provider = Provider.query.filter_by(user_id=session['user_id']).first()
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        service = ProviderService.query.filter_by(
            id=service_id,
            provider_id=provider.id
        ).first()
        
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        db.session.delete(service)
        db.session.commit()
        
        return jsonify({
            'message': 'Service deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ===== UTILITY FUNCTIONS =====

def cleanup_old_files():
    """Clean up old uploaded files"""
    try:
        # This would be called periodically to clean up orphaned files
        # Implementation depends on your cleanup strategy
        pass
    except Exception as e:
        print(f"Error during file cleanup: {e}")

# Export blueprints for registration in main app
__all__ = ['auth_bp', 'user_bp', 'provider_bp']