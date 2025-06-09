from flask import Blueprint, request, jsonify, current_app
from functools import wraps
import logging
import jwt
from datetime import datetime, timedelta
from models import db, User, ProviderService

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create blueprint
service_bp = Blueprint('services', __name__, url_prefix='/api/services')

# ===== JWT HELPER FUNCTIONS =====

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

# ===== JWT DECORATORS =====

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

# ===== SERVICE MANAGEMENT ROUTES =====

@service_bp.route('/', methods=['POST'])
@provider_required
def add_provider_service():
    """Add a new service offering"""
    try:
        current_user = request.current_user
        provider = current_user.provider_profile
        
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
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
            return jsonify({'error': 'Invalid price'}), 400
        
        # Validate duration if provided
        duration_minutes = 60  # default
        if 'duration_minutes' in data:
            try:
                duration_minutes = int(data['duration_minutes'])
                if duration_minutes <= 0:
                    return jsonify({'error': 'Duration must be greater than 0'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid duration'}), 400
        
        # Create new service
        service = ProviderService(
            provider_id=provider.id,
            service_name=data['service_name'],
            description=data['description'],
            price=price,
            duration_minutes=duration_minutes,
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
        logger.error(f"Error adding service: {str(e)}")
        return jsonify({'error': str(e)}), 500

@service_bp.route('/', methods=['GET'])
@provider_required
def get_provider_services():
    """Get all services for the current provider"""
    try:
        current_user = request.current_user
        provider = current_user.provider_profile
        
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        # Get query parameters for filtering
        is_active = request.args.get('is_active')
        search = request.args.get('search', '').strip()
        
        # Build query
        query = ProviderService.query.filter_by(provider_id=provider.id)
        
        # Apply filters
        if is_active is not None:
            is_active_bool = is_active.lower() in ['true', '1', 'yes']
            query = query.filter(ProviderService.is_active == is_active_bool)
        
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                ProviderService.service_name.ilike(search_pattern) |
                ProviderService.description.ilike(search_pattern)
            )
        
        # Order by creation date (newest first)
        services = query.order_by(ProviderService.created_at.desc()).all()
        
        return jsonify({
            'services': [service.to_dict() for service in services],
            'total': len(services)
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting services: {str(e)}")
        return jsonify({'error': str(e)}), 500

@service_bp.route('/<int:service_id>', methods=['PUT'])
@provider_required
def update_provider_service(service_id):
    """Update a provider service"""
    try:
        current_user = request.current_user
        provider = current_user.provider_profile
        
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        service = ProviderService.query.filter_by(
            id=service_id,
            provider_id=provider.id
        ).first()
        
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        # Update allowed fields
        updatable_fields = ['service_name', 'description', 'price', 'duration_minutes', 'is_active']
        
        for field in updatable_fields:
            if field in data:
                if field == 'price':
                    try:
                        price = float(data[field])
                        if price <= 0:
                            return jsonify({'error': 'Price must be greater than 0'}), 400
                        service.price = price
                    except (ValueError, TypeError):
                        return jsonify({'error': 'Invalid price'}), 400
                elif field == 'duration_minutes':
                    try:
                        duration = int(data[field])
                        if duration <= 0:
                            return jsonify({'error': 'Duration must be greater than 0'}), 400
                        service.duration_minutes = duration
                    except (ValueError, TypeError):
                        return jsonify({'error': 'Invalid duration'}), 400
                elif field == 'is_active':
                    service.is_active = bool(data[field])
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
        logger.error(f"Error updating service: {str(e)}")
        return jsonify({'error': str(e)}), 500

@service_bp.route('/<int:service_id>', methods=['DELETE'])
@provider_required
def delete_provider_service(service_id):
    """Delete a provider service"""
    try:
        current_user = request.current_user
        provider = current_user.provider_profile
        
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        service = ProviderService.query.filter_by(
            id=service_id,
            provider_id=provider.id
        ).first()
        
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        # Store service name for response
        service_name = service.service_name
        
        db.session.delete(service)
        db.session.commit()
        
        return jsonify({
            'message': f'Service "{service_name}" deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting service: {str(e)}")
        return jsonify({'error': str(e)}), 500

@service_bp.route('/<int:service_id>', methods=['GET'])
@provider_required
def get_service_details(service_id):
    """Get details of a specific service"""
    try:
        current_user = request.current_user
        provider = current_user.provider_profile
        
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        service = ProviderService.query.filter_by(
            id=service_id,
            provider_id=provider.id
        ).first()
        
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        return jsonify(service.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error getting service details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@service_bp.route('/<int:service_id>/toggle', methods=['POST'])
@provider_required
def toggle_service_status(service_id):
    """Toggle service active/inactive status"""
    try:
        current_user = request.current_user
        provider = current_user.provider_profile
        
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        service = ProviderService.query.filter_by(
            id=service_id,
            provider_id=provider.id
        ).first()
        
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        # Toggle the status
        service.is_active = not service.is_active
        service.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status_text = "activated" if service.is_active else "deactivated"
        
        return jsonify({
            'message': f'Service "{service.service_name}" {status_text} successfully',
            'service': service.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling service status: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ===== PUBLIC SERVICE ROUTES =====

@service_bp.route('/provider/<int:provider_id>', methods=['GET'])
def get_provider_services_public(provider_id):
    """Get all active services for a specific provider - Public endpoint"""
    try:
        # Get query parameters
        search = request.args.get('search', '').strip()
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        
        # Build query for active services only
        query = ProviderService.query.filter_by(
            provider_id=provider_id,
            is_active=True
        )
        
        # Apply search filter
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                ProviderService.service_name.ilike(search_pattern) |
                ProviderService.description.ilike(search_pattern)
            )
        
        # Apply price filters
        if min_price is not None:
            query = query.filter(ProviderService.price >= min_price)
        if max_price is not None:
            query = query.filter(ProviderService.price <= max_price)
        
        # Order by price (lowest first)
        services = query.order_by(ProviderService.price.asc()).all()
        
        return jsonify({
            'services': [service.to_dict() for service in services],
            'total': len(services),
            'provider_id': provider_id
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting public provider services: {str(e)}")
        return jsonify({'error': str(e)}), 500

@service_bp.route('/search', methods=['GET'])
def search_services():
    """Search services across all providers - Public endpoint"""
    try:
        # Get search parameters
        query_text = request.args.get('q', '').strip()
        category = request.args.get('category')
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Start with active services from approved providers
        query = db.session.query(ProviderService).join(
            ProviderService.provider
        ).filter(
            ProviderService.is_active == True,
            # Assuming Provider model has status field
            # Provider.status == 'approved'
        )
        
        # Text search
        if query_text:
            search_pattern = f"%{query_text}%"
            query = query.filter(
                ProviderService.service_name.ilike(search_pattern) |
                ProviderService.description.ilike(search_pattern)
            )
        
        # Price filters
        if min_price is not None:
            query = query.filter(ProviderService.price >= min_price)
        if max_price is not None:
            query = query.filter(ProviderService.price <= max_price)
        
        # Order by price (lowest first)
        query = query.order_by(ProviderService.price.asc())
        
        # Paginate results
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return jsonify({
            'services': [service.to_dict() for service in pagination.items],
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
        logger.error(f"Error searching services: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ===== UTILITY ROUTES =====

@service_bp.route('/categories', methods=['GET'])
def get_service_categories():
    """Get all unique service categories - Public endpoint"""
    try:
        # Get distinct service names from active services
        categories = db.session.query(ProviderService.service_name).filter(
            ProviderService.is_active == True
        ).distinct().all()
        
        category_list = [category[0] for category in categories]
        
        return jsonify({
            'categories': sorted(category_list),
            'total': len(category_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting service categories: {str(e)}")
        return jsonify({'error': str(e)}), 500

@service_bp.route('/stats', methods=['GET'])
@provider_required
def get_service_stats():
    """Get service statistics for current provider"""
    try:
        current_user = request.current_user
        provider = current_user.provider_profile
        
        if not provider:
            return jsonify({'error': 'Provider profile not found'}), 404
        
        # Basic counts
        total_services = ProviderService.query.filter_by(provider_id=provider.id).count()
        active_services = ProviderService.query.filter_by(
            provider_id=provider.id,
            is_active=True
        ).count()
        inactive_services = total_services - active_services
        
        # Average price
        avg_price_result = db.session.query(
            db.func.avg(ProviderService.price)
        ).filter_by(
            provider_id=provider.id,
            is_active=True
        ).scalar()
        
        avg_price = round(float(avg_price_result), 2) if avg_price_result else 0
        
        # Price range
        price_range = db.session.query(
            db.func.min(ProviderService.price),
            db.func.max(ProviderService.price)
        ).filter_by(
            provider_id=provider.id,
            is_active=True
        ).first()
        
        return jsonify({
            'total_services': total_services,
            'active_services': active_services,
            'inactive_services': inactive_services,
            'average_price': avg_price,
            'price_range': {
                'min': float(price_range[0]) if price_range[0] else 0,
                'max': float(price_range[1]) if price_range[1] else 0
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting service stats: {str(e)}")
        return jsonify({'error': str(e)}), 500