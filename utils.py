from models import *
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request



# Role-Based Access Control Decorator
def role_required(roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            current_user = User.query.filter_by(email_id=get_jwt_identity()).first()
            if current_user.role not in roles:
                return jsonify({"msg": "Unauthorized access"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper
