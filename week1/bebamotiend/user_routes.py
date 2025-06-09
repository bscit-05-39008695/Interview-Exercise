from flask import Blueprint, request, jsonify, session
from datetime import datetime, timedelta
from sqlalchemy import or_
from models import db, User
from auth_routes import login_required, admin_required

# Create blueprint
user_bp = Blueprint('users', __name__, url_prefix='/api/users')

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

# Export blueprint
__all__ = ['user_bp']