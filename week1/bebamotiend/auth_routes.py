from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.utils import secure_filename
from functools import wraps
import os
import logging
import uuid
import jwt
from datetime import datetime, timedelta
from models import db, User, Provider

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Configuration for file uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_jwt_token(user_id, role, expires_in_hours=24):
    """Generate JWT token for user"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=expires_in_hours),
        'iat': datetime.utcnow()
    }
    
    secret_key = current_app.config.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
    return jwt.encode(payload, secret_key, algorithm='HS256')

def decode_jwt_token(token):
    """Decode and validate JWT token"""
    try:
        secret_key = current_app.config.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_token_from_request():
    """Extract token from Authorization header or request body"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header.split(' ')[1]
    
    # Fallback to JSON body
    if request.is_json:
        return request.json.get('token')
    
    return None

def login_required(f):
    """Decorator to require login with JWT"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        
        if not token:
            return jsonify({'error': 'Authentication token required'}), 401
        
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Add user info to request context
        request.current_user_id = payload['user_id']
        request.current_user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        
        if not token:
            return jsonify({'error': 'Authentication token required'}), 401
        
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if payload['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        request.current_user_id = payload['user_id']
        request.current_user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated_function

def provider_required(f):
    """Decorator to require service provider role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        
        if not token:
            return jsonify({'error': 'Authentication token required'}), 401
        
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if payload['role'] != 'service_provider':
            return jsonify({'error': 'Service provider access required'}), 403
        
        request.current_user_id = payload['user_id']
        request.current_user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated_function

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
        
        # Generate JWT token
        token = generate_jwt_token(user.id, user.role)
        
        # Set session for backward compatibility
        session['user_id'] = user.id
        session['user_role'] = user.role
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'token': token,
            'dashboard_route': '/client-dashboard' if user.role == 'client' else f'/{user.role}-dashboard'
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
            insurance_proof=uploaded_files['insuranceProof'],
            status='pending'  # Set initial status as pending approval
        )
        
        db.session.add(provider)
        db.session.commit()
        
        # Generate JWT token for the service provider
        token = generate_jwt_token(user.id, user.role)
        
        # Set session for backward compatibility
        session['user_id'] = user.id
        session['user_role'] = user.role
        
        return jsonify({
            'message': 'Provider registration submitted successfully. You can now access your dashboard while your application is pending approval.',
            'user': user.to_dict(),
            'provider': provider.to_dict(),
            'token': token,
            'dashboard_route': '/service-provider-dashboard',
            'status': 'pending_approval'
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
        
        # Generate JWT token
        token = generate_jwt_token(user.id, user.role)
        
        # Set session for backward compatibility
        session['user_id'] = user.id
        session['user_role'] = user.role
        
        # Determine dashboard route based on role
        dashboard_routes = {
            'client': '/client-dashboard',
            'service_provider': '/service-provider-dashboard',
            'admin': '/admin-dashboard'
        }
        
        dashboard_route = dashboard_routes.get(user.role, '/dashboard')
        
        response_data = {
            'message': 'Login successful',
            'user': user.to_dict(),
            'token': token,
            'dashboard_route': dashboard_route
        }
        
        # Add provider status if user is a service provider
        if user.role == 'service_provider':
            provider = Provider.query.filter_by(user_id=user.id).first()
            if provider:
                response_data['provider_status'] = provider.status
                response_data['provider'] = provider.to_dict()
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/users', methods=['GET'])
@login_required
def get_users():
    """Get all users with optional filtering"""
    try:
        # Get query parameters for filtering
        role = request.args.get('role')
        is_active = request.args.get('is_active')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '')
        
        # Limit per_page to prevent excessive data retrieval
        per_page = min(per_page, 100)
        
        # Build query
        query = User.query
        
        # Apply filters
        if role:
            query = query.filter(User.role == role)
        
        if is_active is not None:
            active_status = is_active.lower() == 'true'
            query = query.filter(User.is_active == active_status)
        
        # Apply search filter (search in name and email)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                db.or_(
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern),
                    User.email.ilike(search_pattern)
                )
            )
        
        # Order by creation date (newest first)
        query = query.order_by(User.created_at.desc())
        
        # Paginate results
        paginated_users = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        # Convert users to dict
        users_data = [user.to_dict() for user in paginated_users.items]
        
        # For service providers, include their provider information
        for user_data in users_data:
            if user_data['role'] == 'service_provider':
                provider = Provider.query.filter_by(user_id=user_data['id']).first()
                if provider:
                    user_data['provider_info'] = provider.to_dict()
        
        return jsonify({
            'users': users_data,
            'pagination': {
                'page': paginated_users.page,
                'pages': paginated_users.pages,
                'per_page': paginated_users.per_page,
                'total': paginated_users.total,
                'has_next': paginated_users.has_next,
                'has_prev': paginated_users.has_prev
            },
            'filters': {
                'role': role,
                'is_active': is_active,
                'search': search
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/users/<int:user_id>', methods=['GET'])
@login_required
def get_user_by_id(user_id):
    """Get a specific user by ID"""
    try:
        user = User.find_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user_data = user.to_dict()
        
        # If user is a service provider, include provider information
        if user.role == 'service_provider':
            provider = Provider.query.filter_by(user_id=user.id).first()
            if provider:
                user_data['provider_info'] = provider.to_dict()
        
        return jsonify({
            'user': user_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/providers', methods=['GET'])
@login_required
def get_providers():
    """Get all service providers with optional filtering"""
    try:
        # Get query parameters for filtering
        status = request.args.get('status')
        service_category = request.args.get('service_category')
        min_rate = request.args.get('min_rate', type=float)
        max_rate = request.args.get('max_rate', type=float)
        min_experience = request.args.get('min_experience', type=int)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '')
        
        # Limit per_page to prevent excessive data retrieval
        per_page = min(per_page, 100)
        
        # Join Provider with User to get complete information
        query = db.session.query(Provider, User).join(User, Provider.user_id == User.id)
        
        # Apply filters
        if status:
            query = query.filter(Provider.status == status)
        
        if service_category:
            query = query.filter(Provider.service_category.ilike(f"%{service_category}%"))
        
        if min_rate is not None:
            query = query.filter(Provider.rate_per_hour >= min_rate)
        
        if max_rate is not None:
            query = query.filter(Provider.rate_per_hour <= max_rate)
        
        if min_experience is not None:
            query = query.filter(Provider.experience_years >= min_experience)
        
        # Apply search filter (search in business name, service description, and user names)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                db.or_(
                    Provider.business_name.ilike(search_pattern),
                    Provider.service_description.ilike(search_pattern),
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern)
                )
            )
        
        # Order by creation date (newest first)
        query = query.order_by(Provider.created_at.desc())
        
        # Get total count for pagination
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        provider_user_pairs = query.offset(offset).limit(per_page).all()
        
        # Convert to response format
        providers_data = []
        for provider, user in provider_user_pairs:
            provider_dict = provider.to_dict()
            provider_dict['user_info'] = user.to_dict()
            providers_data.append(provider_dict)
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page  # Ceiling division
        has_next = page < pages
        has_prev = page > 1
        
        return jsonify({
            'providers': providers_data,
            'pagination': {
                'page': page,
                'pages': pages,
                'per_page': per_page,
                'total': total,
                'has_next': has_next,
                'has_prev': has_prev
            },
            'filters': {
                'status': status,
                'service_category': service_category,
                'min_rate': min_rate,
                'max_rate': max_rate,
                'min_experience': min_experience,
                'search': search
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/providers/<int:provider_id>', methods=['GET'])
@login_required
def get_provider_by_id(provider_id):
    """Get a specific provider by ID"""
    try:
        # Join Provider with User to get complete information
        result = db.session.query(Provider, User).join(
            User, Provider.user_id == User.id
        ).filter(Provider.id == provider_id).first()
        
        if not result:
            return jsonify({'error': 'Provider not found'}), 404
        
        provider, user = result
        provider_data = provider.to_dict()
        provider_data['user_info'] = user.to_dict()
        
        return jsonify({
            'provider': provider_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/providers/by-user/<int:user_id>', methods=['GET'])
@login_required
def get_provider_by_user_id(user_id):
    """Get provider information by user ID"""
    try:
        provider = Provider.query.filter_by(user_id=user_id).first()
        
        if not provider:
            return jsonify({'error': 'Provider profile not found for this user'}), 404
        
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        provider_data = provider.to_dict()
        provider_data['user_info'] = user.to_dict()
        
        return jsonify({
            'provider': provider_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# NEW ENDPOINT: Get providers by service category
@auth_bp.route('/providers/by-category/<string:service_category>', methods=['GET'])
@login_required
def get_providers_by_category(service_category):
    """Get providers filtered by specific service category"""
    try:
        # Map frontend service types to backend service categories
        service_type_mapping = {
            'towing': 'towing',
            'battery': 'battery',
            'tire': 'tire',
            'fuel': 'fuel',
            'lockout': 'lockout'
        }
        
        # Use the mapping or fall back to the original category
        mapped_category = service_type_mapping.get(service_category.lower(), service_category)
        
        # Get additional query parameters
        status = request.args.get('status', 'pending')  # Default to pending providers
        min_rate = request.args.get('min_rate', type=float)
        max_rate = request.args.get('max_rate', type=float)
        min_experience = request.args.get('min_experience', type=int)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search', '')
        sort_by = request.args.get('sort_by', 'created_at')  # created_at, rate_per_hour, experience_years
        sort_order = request.args.get('sort_order', 'desc')  # asc, desc
        
        # Limit per_page to prevent excessive data retrieval
        per_page = min(per_page, 100)
        
        # Join Provider with User to get complete information
        query = db.session.query(Provider, User).join(User, Provider.user_id == User.id)
        
        # Filter by service category (case-insensitive)
        query = query.filter(Provider.service_category.ilike(f"%{mapped_category}%"))
        
        # Apply additional filters
        if status:
            query = query.filter(Provider.status == status)
        
        if min_rate is not None:
            query = query.filter(Provider.rate_per_hour >= min_rate)
        
        if max_rate is not None:
            query = query.filter(Provider.rate_per_hour <= max_rate)
        
        if min_experience is not None:
            query = query.filter(Provider.experience_years >= min_experience)
        
        # Apply search filter
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                db.or_(
                    Provider.business_name.ilike(search_pattern),
                    Provider.service_description.ilike(search_pattern),
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern)
                )
            )
        
        # Apply sorting
        if sort_by == 'rate_per_hour':
            order_column = Provider.rate_per_hour
        elif sort_by == 'experience_years':
            order_column = Provider.experience_years
        elif sort_by == 'business_name':
            order_column = Provider.business_name
        else:
            order_column = Provider.created_at
        
        if sort_order.lower() == 'asc':
            query = query.order_by(order_column.asc())
        else:
            query = query.order_by(order_column.desc())
        
        # Get total count for pagination
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        provider_user_pairs = query.offset(offset).limit(per_page).all()
        
        # Convert to response format
        providers_data = []
        for provider, user in provider_user_pairs:
            provider_dict = provider.to_dict()
            provider_dict['user_info'] = user.to_dict()
            providers_data.append(provider_dict)
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        has_next = page < pages
        has_prev = page > 1
        
        return jsonify({
            'providers': providers_data,
            'service_category': mapped_category,
            'original_category': service_category,
            'total_found': total,
            'pagination': {
                'page': page,
                'pages': pages,
                'per_page': per_page,
                'total': total,
                'has_next': has_next,
                'has_prev': has_prev
            },
            'filters_applied': {
                'service_category': mapped_category,
                'status': status,
                'min_rate': min_rate,
                'max_rate': max_rate,
                'min_experience': min_experience,
                'search': search,
                'sort_by': sort_by,
                'sort_order': sort_order
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting providers by category {service_category}: {str(e)}")
        return jsonify({'error': str(e)}), 500

# NEW ENDPOINT: Get available service categories
@auth_bp.route('/providers/categories', methods=['GET'])
@login_required
def get_available_service_categories():
    """Get all available service categories"""
    try:
        # Get distinct service categories from the database
        categories = db.session.query(Provider.service_category).distinct().all()
        category_list = [category[0] for category in categories if category[0]]
        
        # Map backend categories to frontend service types
        service_type_mapping = {
            'towing': 'towing',
            'battery': 'battery', 
            'tire': 'tire',
            'fuel': 'fuel',
            'lockout': 'lockout'
        }
        
        # Get counts for each category
        category_counts = {}
        for category in category_list:
            count = Provider.query.filter(
                Provider.service_category.ilike(f"%{category}%"),
                Provider.status == 'pending'
            ).count()
            category_counts[category] = count
        
        return jsonify({
            'categories': category_list,
            'category_counts': category_counts,
            'service_type_mapping': service_type_mapping
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting service categories: {str(e)}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/refresh-token', methods=['POST'])
@login_required
def refresh_token():
    """Refresh JWT token"""
    try:
        user = User.find_by_id(request.current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate new token
        new_token = generate_jwt_token(user.id, user.role)
        
        return jsonify({
            'message': 'Token refreshed successfully',
            'token': new_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/verify-token', methods=['POST'])
def verify_token():
    """Verify JWT token validity"""
    try:
        token = get_token_from_request()
        
        if not token:
            return jsonify({'error': 'Token required', 'valid': False}), 400
        
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token', 'valid': False}), 401
        
        user = User.find_by_id(payload['user_id'])
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive', 'valid': False}), 401
        
        return jsonify({
            'valid': True,
            'user_id': payload['user_id'],
            'role': payload['role'],
            'expires_at': payload['exp']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e), 'valid': False}), 500


# Export decorators and blueprint for use in other route files
__all__ = ['auth_bp', 'login_required', 'admin_required', 'provider_required', 'generate_jwt_token', 'decode_jwt_token']