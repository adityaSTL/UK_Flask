

from flask import Blueprint
from models import User
from flask import Flask, request, jsonify
from conf import app, db, engine, swagger, bcrypt, jwt, migrate, swagger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from utils import role_required
from helper_func import *
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from flask_jwt_extended import decode_token
from werkzeug.utils import secure_filename
import os
from flask_cors import CORS

users_blueprint = Blueprint('users', __name__)

CORS(app)



UPLOAD_FOLDER = '/home/administrator/flask/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@users_blueprint.route('/test')
def home():
    return "Users Test"



@users_blueprint.route('/login', methods=['POST'])
def login():
    """
    User Login
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            email_id:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
        schema:
          type: object
          properties:
            access_token:
              type: string
            role:
              type: string
            can_edit:
              type: boolean
            id:
              type: integer
      400:
        description: Missing or invalid data
      401:
        description: Invalid username or password
    """
    # Parse the request JSON
    data = request.get_json()

    # Check if required fields are present
    if not data or not data.get('email_id') or not data.get('password'):
        return jsonify({"msg": "Missing email_id or password"}), 400

    email_id = data.get('email_id').strip().lower() if data.get('email_id') else None
    password = data.get('password').strip() if data.get('password') else None

    # Validate fields are not empty after trimming
    if not email_id or not password:
        return jsonify({"msg": "email_id or password cannot be empty"}), 400

    # Query the user from the database
    user = User.query.filter_by(email_id=email_id).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Create access token (assuming Flask-JWT-Extended is used)
        access_token = create_access_token(identity=user.email_id)

        return jsonify(
            access_token=access_token,
            role=user.role,
            can_edit=user.can_edit,
            id=user.id
        ), 200

    # Invalid credentials
    return jsonify({"msg": "Invalid email_id or password"}), 401


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@users_blueprint.route('/register', methods=['POST'])
@role_required(['admin'])
@jwt_required()
def register_user():
    """
    Register a new user with optional profile image
    ---
    tags:
      - User Management
    security:
      - JWT: []
    parameters:
      - name: username
        in: formData
        required: true
        type: string
      - name: password
        in: formData
        required: true
        type: string
      - name: email_id
        in: formData
        required: true
        type: string
      - name: phone_no
        in: formData
        required: false
        type: string
      - name: role
        in: formData
        required: true
        type: string
      - name: can_edit
        in: formData
        required: false
        type: boolean
      - name: profile_image
        in: formData
        required: false
        type: file
        description: Profile image for the new user (optional, .jpg/.png formats only)
    responses:
      201:
        description: User registered successfully
      400:
        description: Bad request
      401:
        description: Unauthorized access
      403:
        description: Forbidden - User does not have admin role
    """
    data = request.form
    username = data.get('username')
    password = data.get('password')
    email_id = data.get('email_id')
    phone_no = data.get('phone_no')
    role = data.get('role')
    can_edit = data.get('can_edit', False)

    # Set can_edit based on role
    if role == 'admin' or role == 'editor':
        can_edit = True
    else:
        can_edit = data.get('can_edit', False)  # Use provided value or default to False

    profile_image = request.files.get('profile_image')

    if not username or not password or not email_id or not role:
        return jsonify({'error': 'Username, password, email_id, and role are required'}), 400

    if validate_email_id(email_id) == 0:
        return jsonify({'error': 'Email Id does not exist'}), 400

    if User.query.filter_by(email_id=email_id).first():
        return jsonify({'error': 'User already exists'}), 400

    if profile_image:
        if allowed_file(profile_image.filename):
            filename = secure_filename(profile_image.filename)
            profile_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return jsonify({'error': 'Invalid file type, only JPG and PNG are allowed'}), 400
    else:
        filename = None  # Default if no image is provided

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, email_id=email_id, phone_no=phone_no, role=role, can_edit=can_edit, profile_image=filename)
    
    db.session.add(new_user)
    db.session.commit()
    send_welcome_email(email_id, password, username)

    return jsonify({'message': 'User registered successfully'}), 201




@users_blueprint.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    User Logout
    ---
    tags:
      - Authentication
    security:
      - JWT: []
    responses:
      200:
        description: Logout successful
        schema:
          type: object
          properties:
            message:
              type: string
              example: Logout successful
      401:
        description: Unauthorized - Invalid or missing token
    """
    return jsonify({'message': 'Logout successful'}), 200



# Update the forgot password API to use email_id
@users_blueprint.route('/forgot_password', methods=['POST'])
def forgot_password():
    """
    Request Password Reset
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - email_id
          properties:
            email_id:
              type: string
              description: Email address of the user requesting password reset
    responses:
      200:
        description: Password reset link sent successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: Password reset link has been sent
      400:
        description: Bad request - Email ID is missing
        schema:
          type: object
          properties:
            error:
              type: string
              example: Email ID is required
      404:
        description: User not found
        schema:
          type: object
          properties:
            error:
              type: string
              example: User not found
    """
    data = request.json
    email_id = data.get('email_id')

    if not email_id:
        return jsonify({'error': 'Email ID is required'}), 400

    user = User.query.filter_by(email_id=email_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a password reset token (you can use JWT or other methods)
    reset_token = create_access_token(identity=email_id, expires_delta=timedelta(hours=1))

    # Send the reset token via email
    # send_reset_email(email_id, reset_token)

    return jsonify({'message': 'Password reset link not sent', 'reset_token': reset_token}), 200




# Update the reset password API to use email_id
@users_blueprint.route('/reset_password', methods=['POST'])
def reset_password():
    """
    Reset User Password
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - reset_token
            - new_password
          properties:
            reset_token:
              type: string
              description: Token received in the password reset email
            new_password:
              type: string
              description: New password to set for the user
    responses:
      200:
        description: Password reset successful
        schema:
          type: object
          properties:
            message:
              type: string
              example: Password reset successfully
      400:
        description: Bad request - Missing required fields or invalid token
        schema:
          type: object
          properties:
            error:
              type: string
              example: Reset token and new password are required
      404:
        description: User not found
        schema:
          type: object
          properties:
            error:
              type: string
              example: User not found
    """
    data = request.json
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')
    print(reset_token)

    if not reset_token or not new_password:
        return jsonify({'error': 'Reset token and new password are required'}), 400

    try:
        # Decode the reset token to get the email_id
        token_data = decode_token(reset_token)
        print(token_data)
        email_id = token_data['sub']  # 'sub' is where the identity is stored
        # email_id = jwt.decode_token(reset_token)['identity']
        print(email_id)
    except ExpiredSignatureError:
        return jsonify({'error': 'Expired token'}), 400
    except InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 400
    except Exception as e:
        print(f"Unexpected error decoding token: {str(e)}")
        return jsonify({'error': 'Error decoding token'}), 400

    user = User.query.filter_by(email_id=email_id).first()
    print(user)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    print("Password reset done")
    db.session.commit()

    return jsonify({'message': 'Password reset successfully'}), 200


@users_blueprint.route('/testa')
def testa():
    try:
        users = User.query.all()
        return jsonify({"users": [user.to_dict() for user in users]})
    except Exception as e:
        return jsonify({"error": str(e)})



# Read a single user (if ID) else multiple users
@users_blueprint.route('/users', methods=['GET'])
@users_blueprint.route('/users/<int:id>', methods=['GET'])
@jwt_required()
@role_required(['admin'])
def get_users(id=None):
    if id:
        # Fetch a single user by ID
        try:
          user = User.query.get(id)
          if not user:
              return jsonify({"error": "User not found"}), 404
          return jsonify(user.to_dict()), 200
        except Exception as e:
          return jsonify({"error": str(e)})

    else:
        # Fetch all users if no ID is provided
        try:
          users = User.query.all()
          return jsonify([user.to_dict() for user in users]), 200
        except Exception as e:
          return jsonify({"error": str(e)})  



# Update a user
@users_blueprint.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user = User.query.filter_by(email_id=get_jwt_identity()).first()  # Get the currently logged-in user
    user = User.query.get(id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not current_user:
        return jsonify({"error": "User not found"}), 404


    # Ensure non-admin users can only update their own data
    if current_user.id != user.id and current_user.role != 'admin':
        return jsonify({"error": "You can only update your own details unless you're an admin."}), 403

    data = request.form  # Use request.form to get text data
    profile_image = request.files.get('profile_image')  # Use request.files for the image

    # Allow updating username, password, email, phone_no, and can_edit
    if 'username' in data:
        user.username = data['username']
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='sha256')
    if 'email_id' in data:
        user.email_id = data['email_id']
    if 'phone_no' in data:
        user.phone_no = data['phone_no']

    # Role update is only allowed for admins
    if 'role' in data:
        if current_user.role=='admin':
            user.role = data['role']
        else:
            return jsonify({"error": "You are not authorized to update the role."}), 403

    # Handling profile image update
    if profile_image:
        if allowed_file(profile_image.filename):
            filename = secure_filename(profile_image.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Save the new profile image
            profile_image.save(file_path)
            
            # Update the profile_image path in the database
            user.profile_image = filename
        else:
            return jsonify({"error": "Invalid file type. Only JPG and PNG are allowed."}), 400

    db.session.commit()
    return jsonify({"message": "User updated successfully", "user": user.to_dict()}), 200


# Delete a user
@users_blueprint.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'editor'])
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200

