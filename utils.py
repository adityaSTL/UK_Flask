from models import *
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request



# Role-Based Access Control Decorator
def role_required(roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()  # Ensure that JWT is verified first
        def wrapper(*args, **kwargs):
            try:
                # Verify the JWT and get the current user
                verify_jwt_in_request()
                current_user_email = get_jwt_identity()
                current_user = User.query.filter_by(email_id=current_user_email).first()
                
                # Check if the user exists and if the role is authorized
                if not current_user:
                    return jsonify({"msg": "User not found"}), 404
                
                if current_user.role not in roles:
                    return jsonify({"msg": "Unauthorized access"}), 403
                
                # Proceed to the original function if all checks pass
                return fn(*args, **kwargs)
            
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        return wrapper
    return decorator


