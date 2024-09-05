from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import DECIMAL
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import func
import os
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
import pandas as pd
from sqlalchemy import create_engine
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sqlalchemy.orm import relationship, foreign, remote
from sqlalchemy import MetaData, Table, select
from sqlalchemy import func, case, cast, Float
from sqlalchemy import inspect
from sqlalchemy import func, extract, and_
import numpy as np
from flasgger import Swagger
import calendar
from email_validator import validate_email, EmailNotValidError
from validate_email_address import validate_email as validate_existence



db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_name = os.getenv('DB_NAME')
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqldb://root:Admin%40123@10.100.130.76/eod"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', '1234567890') # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)



app.config['SWAGGER'] = {
    'title': 'Flask UK',
    'uiversion': 3,
    'version': '1.0',
    'description': 'List of All APIs with documentation',
    'termsOfService': 'http://example.com/terms',
    'contact': {
        'name': 'Flask UK',
        'url': 'https://stl.tech',
        'email': 'automation.gsb@stl.tech'
    },
    'license': {
        'name': 'Apache 2.0',
        'url': 'https://www.apache.org/licenses/LICENSE-2.0.html'
    }
}
swagger = Swagger(app)


CORS(app)
# swagger = Swagger(app)





bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)


engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email_id = db.Column(db.String(120), unique=True, nullable=False)
    phone_no = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)
    # name = db.Column(db.String(100), default=False)
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class PnRaw(db.Model):
    __tablename__ = 'pn_raw'
    unique_id = db.Column(db.String(100), primary_key=True)
    payment_notice_id = db.Column(db.String(100))
    contractor_afp_ref = db.Column(db.String(100))
    pn_date_issued_to_contractor = db.Column(db.Date)
    date_of_application = db.Column(db.Date)
    purchase_order_id = db.Column(db.String(100))
    region = db.Column(db.String(100))
    exchange_id = db.Column(db.String(100))
    town = db.Column(db.String(100))
    contractor = db.Column(db.String(100))
    polygon_type = db.Column(db.String(100))
    polygon_id = db.Column(db.String(100))
    feature_id = db.Column(db.String(100))
    build_status = db.Column(db.String(100))
    code = db.Column(db.String(100))
    item = db.Column(db.String(255))
    unit = db.Column(db.String(100))
    price = db.Column(db.DECIMAL(10, 5))
    quantity = db.Column(db.DECIMAL(10, 5))
    total = db.Column(db.DECIMAL(10, 2))
    comments = db.Column(db.String(255))
    afp_claim_ok_nok = db.Column(db.String(100))
    nok_reason_code = db.Column(db.String(100))
    approved_quantity = db.Column(db.DECIMAL(10, 5))
    approved_total = db.Column(db.DECIMAL(10, 5))
    concate = db.Column(db.String(100))
    qgis_quant = db.Column(db.DECIMAL(10, 5))
    qgis_rate = db.Column(db.DECIMAL(10, 5))
    qgis_url = db.Column(db.String(255))
    po_check = db.Column(db.String(100))
    comment = db.Column(db.String(255))
    comment_stl=db.Column(db.String(255))
    resubmission = db.Column(db.Boolean, default=False)
    seed = db.Column(db.Integer, db.ForeignKey('eod_dump.Seed'))


    def to_dict(self):
        """Convert the SQLAlchemy object to a dictionary."""
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

class WorkCat(db.Model):
    __tablename__ = 'work_cat'
    id = db.Column(db.Integer, primary_key=True)  # New primary key column
    Rate_Code = db.Column(db.String(255))  # Existing column
    Category = db.Column(db.String(255))

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
        
class SubcontractorRate(db.Model):
    __tablename__ = 'subcontractor_rate'
    id = db.Column(db.Integer, primary_key=True)
    rate_code = db.Column(db.String(10), nullable=False)
    work_category = db.Column(db.String(50), nullable=False)
    rate_type = db.Column(db.String(50), nullable=False)
    item = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(50), nullable=False)
    heavy_and_dirty = db.Column(db.String(50), nullable=True)
    include_hnd_in_service_price = db.Column(db.String(3), nullable=True)
    description = db.Column(db.Text, nullable=True)
    afs = db.Column(db.DECIMAL(10, 2), nullable=True)
    bk_comms = db.Column(db.DECIMAL(10, 2), nullable=True)
    ccg = db.Column(db.DECIMAL(10, 2), nullable=True)
    jk_comms = db.Column(db.DECIMAL(10, 2), nullable=True)
    jdc = db.Column(db.DECIMAL(10, 2), nullable=True)
    jto = db.Column(db.DECIMAL(10, 2), nullable=True)
    nola = db.Column(db.DECIMAL(10, 2), nullable=True)
    rollo = db.Column(db.DECIMAL(10, 2), nullable=True)
    salcs = db.Column(db.DECIMAL(10, 2), nullable=True)
    upscale = db.Column(db.DECIMAL(10, 2), nullable=True)
    vsl = db.Column(db.DECIMAL(10, 2), nullable=True)
    vus = db.Column(db.DECIMAL(10, 2), nullable=True)
    set = db.Column(db.DECIMAL(10, 2), nullable=True)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}



class ClientRate(db.Model):
    __tablename__ = 'client_rate'
    id = db.Column(db.Integer, primary_key=True)
    rate_code = db.Column(db.String(50))
    rate_type = db.Column(db.String(255))
    item = db.Column(db.String(255))
    unit = db.Column(db.String(50))
    heavy_and_dirty = db.Column(db.String(25))
    include_hnd_in_service_price = db.Column(db.String(25))
    rates = db.Column(db.String(255))
    comments = db.Column(db.String(255))

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class UserRevenue(db.Model):
    __tablename__ = 'user_revenue'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(255), nullable=False)
    revenue_generating_entity = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'revenue_generating_entity': self.revenue_generating_entity
        }





class EODDump(db.Model):
    __tablename__ = 'eod_dump'
    Date = db.Column(db.Date)
    TeamLeader = db.Column(db.String(255))
    Gang = db.Column(db.String(255))
    Work_Type = db.Column(db.String(255))
    Item_Mst_ID = db.Column(db.String(255))
    Item_Description = db.Column(db.String(255))
    Activity = db.Column(db.String(255))
    WeekNumber = db.Column(db.String(255))
    Output_Date_MonthYear = db.Column(db.String(255))
    Qty = db.Column(db.Integer)
    UOM = db.Column(db.String(255))
    Rate = db.Column(DECIMAL(10, 2))
    Total = db.Column(DECIMAL(10, 2))
    Area = db.Column(db.String(255))
    Mst_Item_Rpt_Group1 = db.Column(db.String(255))
    Project_ID = db.Column(db.Integer)
    Project_Name = db.Column(db.String(255))
    Seed = db.Column(db.Integer, primary_key=True)
    Comment = db.Column(db.Text)
    Planning_KPI1 = db.Column(db.String(255))
    Email_ID = db.Column(db.String(255))
    User_Name = db.Column(db.String(255))
    AuditLog = db.Column(db.String(255))
    Work_Period = db.Column(db.String(255))
    Job_Pack_No = db.Column(db.String(255))
    Route = db.Column(db.String(255))
    Work_Category = db.Column(db.String(255))
    Approved_Status = db.Column(db.String(255))
    PMO_Coordinator = db.Column(db.String(255))
    QA_remarks = db.Column(db.Text)
    Span_length = db.Column(db.String(255))
    # Qty_2 = db.Column(db.Integer)
    Taken_To_Revenue = db.Column(db.Boolean)
    Taken_To_Revenue_Date = db.Column(db.DateTime, nullable=True)
    
    user_revenue = relationship(
        "UserRevenue",
        primaryjoin=foreign(func.lower(User_Name)) == remote(func.lower(UserRevenue.user_name)),
        viewonly=True
    )

    work_cat = relationship(
        "WorkCat",
        primaryjoin=foreign(Item_Mst_ID) == remote(WorkCat.Rate_Code),
        viewonly=True
    )

    def to_dict(self):
        result = {column.name: getattr(self, column.name) for column in self.__table__.columns}
        result['Date'] = self.Date.strftime('%d-%m-%Y') if self.Date else None
        return result
        # return {column.name: getattr(self, column.name) for column in self.__table__.columns}



def validate_email_id(email):
    try:
        # Step 1: Validate the syntax of the email
        valid = validate_email(email)
        normalized_email = valid.email  # Get the normalized form of the email (lowercase, no extra spaces, etc.)

        # Step 2: Check if the domain and email exist (MX and SMTP check)
        # if validate_existence(email, verify=True):
        #     print(f"Email '{normalized_email}' is valid and exists.")
        #     return 1

        if valid:
            print(f"Email '{normalized_email}' has a valid syntax but may not exist (SMTP check not done).")
            return 1
    
    except EmailNotValidError as e:
        # Handle invalid email syntax
        print(f"Invalid email syntax: {str(e)}")
        return 0


def send_welcome_email(to_email, password,name):
    
    # print(reset_token)
    # Gmail credentials
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    from_email = 'stlautomation123@gmail.com'
    password = 'thyuysdcdonpymsr'

    # Create the email content
    subject = 'Welcome to XX Portal'
    body = '''
    Hi {name},

    We welcome you to STL UK project management portal. 
    
    Here are your credential to login the portal

    Portal Link: "http://10.100.130.76:5000"
    Username: {name}
    Email id: {to_email}
    Password: {password}

    Kindly change password after login for security reasons and update your profile. 
    
    Happy Exploring!!
    Team Automation
    automation.gsb@stl.tech
    '''.format(name=name, to_email=to_email, password=password)

    # Create a MIMEText object and set up the email headers
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the Gmail SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()

        print('Email sent successfully')
    except Exception as e:
        print(f'Failed to send email: {e}')


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








@app.route('/api/register', methods=['POST'])
@role_required(['admin'])
@jwt_required()
def register_user():
    """
    Register a new user
    ---
    tags:
      - User Management
    security:
      - JWT: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
            - email_id
            - role
          properties:
            username:
              type: string
              description: Unique username for the new user
            password:
              type: string
              description: Password for the new user
            email_id:
              type: string
              description: Unique email address for the new user
            phone_no:
              type: string
              description: Phone number of the new user (optional)
            role:
              type: string
              description: Role of the new user (e.g., admin, editor, viewer)
            can_edit:
              type: boolean
              description: Whether the user has edit permissions (default is false)
    responses:
      201:
        description: User registered successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: User registered successfully
      400:
        description: Bad request
        schema:
          type: object
          properties:
            error:
              type: string
              example: Username, password, email_id, and role are required
      401:
        description: Unauthorized access
      403:
        description: Forbidden - User does not have admin role
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email_id = data.get('email_id')
    phone_no = data.get('phone_no')
    role = data.get('role')
    can_edit = data.get('can_edit', False)
    print(username,password,email_id,phone_no,role,can_edit)


    
    if not username or not password or not email_id or not role:
        return jsonify({'error': 'Username, password, email_id, and role are required'}), 400

    if validate_email_id(email_id)==0:
        return jsonify({'error': 'Email Id does not exists'}), 400

    if User.query.filter_by(email_id=email_id).first():
        return jsonify({'error': 'User already exists'}), 400

    if User.query.filter_by(email_id=email_id).first():
        return jsonify({'error': 'Email ID already in use'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, email_id=email_id, phone_no=phone_no, role=role, can_edit=can_edit)
    db.session.add(new_user)
    send_welcome_email(email_id,password,username)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201





# PUT request to update an existing user revenue record
@app.route('/api/user_revenue/<int:id>', methods=['PUT'])
def update_user_revenue(id):
    # Fetch the user revenue by ID
    user_revenue = UserRevenue.query.get_or_404(id)

    # Get the data from the request
    data = request.json

    # Update fields if they are provided in the request
    user_revenue.user_name = data.get('user_name', user_revenue.user_name)
    user_revenue.revenue_generating_entity = data.get('revenue_generating_entity', user_revenue.revenue_generating_entity)

    # Commit changes to the database
    db.session.commit()

    return jsonify(user_revenue.to_dict()), 200



# DELETE request to delete a user revenue record by ID
@app.route('/api/user_revenue/<int:id>', methods=['DELETE'])
def delete_user_revenue(id):
    # Fetch the user revenue by ID
    user_revenue = UserRevenue.query.get_or_404(id)

    # Delete the record from the database
    db.session.delete(user_revenue)
    db.session.commit()

    return jsonify({"message": "User revenue deleted successfully"}), 200



@app.route('/api/edit_eod_dump/<int:seed>', methods=['PUT'])
@jwt_required()
@role_required(['admin', 'editor'])
def edit_eod_dump(seed):
    # Get the record based on the primary key (Seed)
    record = EODDump.query.get(seed)
    
    if not record:
        return jsonify({'error': 'Record not found'}), 404

    # Update the fields from the request data
    data = request.json

    # List of allowed fields to update
    allowed_fields = [
        'Date', 'TeamLeader', 'Gang', 'Work_Type', 'Item_Mst_ID', 'Item_Description',
        'Activity', 'WeekNumber', 'Output_Date_MonthYear', 'Qty', 'UOM', 'Rate', 'Total',
        'Area', 'Mst_Item_Rpt_Group1', 'Project_ID', 'Project_Name', 'Comment',
        'Planning_KPI1', 'Email_ID', 'User_Name', 'AuditLog', 'Work_Period', 'Job_Pack_No',
        'Route', 'Work_Category', 'Approved_Status', 'PMO_Coordinator', 'QA_remarks', 
        'Span_length', 'Taken_To_Revenue', 'Taken_To_Revenue_Date'
    ]

    for field in allowed_fields:
        if field in data:
            setattr(record, field, data[field])

    try:
        db.session.commit()
        return jsonify({'message': 'Record updated successfully', 'record': record.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/api/pn_raw/<unique_id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'editor'])
def delete_pn_raw(unique_id):
    try:
        # Query the PnRaw table to find the record with the given unique_id
        record = db.session.query(PnRaw).filter(PnRaw.unique_id == unique_id).first()
        
        # Check if the record exists
        if record is None:
            return jsonify({"message": "Record not found"}), 404
        
        # Delete the record
        db.session.delete(record)
        db.session.commit()
        
        return jsonify({"message": "Record deleted successfully"}), 200
    
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({"error": str(e)}), 500


@app.route('/api/work_cat', methods=['POST'])
@jwt_required()
def create_work_cat():
    data = request.json
    new_work_cat = WorkCat(
        Rate_Code=data.get('Rate_Code'),
        Category=data.get('Category')
    )
    db.session.add(new_work_cat)
    db.session.commit()
    return jsonify(new_work_cat.to_dict()), 201

@app.route('/api/subcontractor_rate', methods=['POST'])
@jwt_required()
def create_subcontractor_rate():
    data = request.json
    new_rate = SubcontractorRate(
        rate_code=data.get('rate_code'),
        work_category=data.get('work_category'),
        rate_type=data.get('rate_type'),
        item=data.get('item'),
        unit=data.get('unit'),
        heavy_and_dirty=data.get('heavy_and_dirty'),
        include_hnd_in_service_price=data.get('include_hnd_in_service_price'),
        description=data.get('description'),
        afs=data.get('afs'),
        bk_comms=data.get('bk_comms'),
        ccg=data.get('ccg'),
        jk_comms=data.get('jk_comms'),
        jdc=data.get('jdc'),
        jto=data.get('jto'),
        nola=data.get('nola'),
        rollo=data.get('rollo'),
        salcs=data.get('salcs'),
        upscale=data.get('upscale'),
        vsl=data.get('vsl'),
        vus=data.get('vus'),
        set=data.get('set')
    )
    db.session.add(new_rate)
    db.session.commit()
    return jsonify(new_rate.to_dict()), 201

@app.route('/api/client_rate', methods=['POST'])
@jwt_required()
def create_client_rate():
    data = request.json
    new_client_rate = ClientRate(
        rate_code=data.get('rate_code'),
        rate_type=data.get('rate_type'),
        item=data.get('item'),
        unit=data.get('unit'),
        heavy_and_dirty=data.get('heavy_and_dirty'),
        include_hnd_in_service_price=data.get('include_hnd_in_service_price'),
        rates=data.get('rates'),
        comments=data.get('comments')
    )
    db.session.add(new_client_rate)
    db.session.commit()
    return jsonify(new_client_rate.to_dict()), 201

@app.route('/api/user_revenue', methods=['POST'])
@jwt_required()
def create_user_revenue():
    data = request.json
    new_user_revenue = UserRevenue(
        user_name=data.get('user_name'),
        revenue_generating_entity=data.get('revenue_generating_entity')
    )
    db.session.add(new_user_revenue)
    db.session.commit()
    return jsonify(new_user_revenue.to_dict()), 201


# PUT request to update an existing subcontractor rate
@app.route('/api/subcontractor_rate/<int:id>', methods=['PUT'])
@jwt_required()
@role_required(['admin', 'editor'])
def update_subcontractor_rate(id):
    # Fetch the subcontractor rate by ID
    subcontractor_rate = SubcontractorRate.query.get_or_404(id)

    # Get the data from the request
    data = request.json

    # Update fields if they are provided in the request
    subcontractor_rate.rate_code = data.get('rate_code', subcontractor_rate.rate_code)
    subcontractor_rate.work_category = data.get('work_category', subcontractor_rate.work_category)
    subcontractor_rate.rate_type = data.get('rate_type', subcontractor_rate.rate_type)
    subcontractor_rate.item = data.get('item', subcontractor_rate.item)
    subcontractor_rate.unit = data.get('unit', subcontractor_rate.unit)
    subcontractor_rate.heavy_and_dirty = data.get('heavy_and_dirty', subcontractor_rate.heavy_and_dirty)
    subcontractor_rate.include_hnd_in_service_price = data.get('include_hnd_in_service_price', subcontractor_rate.include_hnd_in_service_price)
    subcontractor_rate.description = data.get('description', subcontractor_rate.description)
    subcontractor_rate.afs = data.get('afs', subcontractor_rate.afs)
    subcontractor_rate.bk_comms = data.get('bk_comms', subcontractor_rate.bk_comms)
    subcontractor_rate.ccg = data.get('ccg', subcontractor_rate.ccg)
    subcontractor_rate.jk_comms = data.get('jk_comms', subcontractor_rate.jk_comms)
    subcontractor_rate.jdc = data.get('jdc', subcontractor_rate.jdc)
    subcontractor_rate.jto = data.get('jto', subcontractor_rate.jto)
    subcontractor_rate.nola = data.get('nola', subcontractor_rate.nola)
    subcontractor_rate.rollo = data.get('rollo', subcontractor_rate.rollo)
    subcontractor_rate.salcs = data.get('salcs', subcontractor_rate.salcs)
    subcontractor_rate.upscale = data.get('upscale', subcontractor_rate.upscale)
    subcontractor_rate.vsl = data.get('vsl', subcontractor_rate.vsl)
    subcontractor_rate.vus = data.get('vus', subcontractor_rate.vus)
    subcontractor_rate.set = data.get('set', subcontractor_rate.set)

    # Commit changes to the database
    db.session.commit()

    return jsonify(subcontractor_rate.to_dict()), 200

# DELETE request to delete a subcontractor rate by ID
@app.route('/api/subcontractor_rate/<int:id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'editor'])
def delete_subcontractor_rate(id):
    # Fetch the subcontractor rate by ID
    subcontractor_rate = SubcontractorRate.query.get_or_404(id)

    # Delete the record from the database
    db.session.delete(subcontractor_rate)
    db.session.commit()

    return jsonify({"message": "Subcontractor rate card deleted successfully"}), 200    


# PUT request to update an existing client rate
@app.route('/api/client_rate/<int:id>', methods=['PUT'])
@jwt_required()
@role_required(['admin', 'editor'])
def update_client_rate(id):
    # Fetch the client rate by ID
    client_rate = ClientRate.query.get_or_404(id)

    # Get the data from the request
    data = request.json

    # Update fields if they are provided in the request
    client_rate.rate_code = data.get('rate_code', client_rate.rate_code)
    client_rate.rate_type = data.get('rate_type', client_rate.rate_type)
    client_rate.item = data.get('item', client_rate.item)
    client_rate.unit = data.get('unit', client_rate.unit)
    client_rate.heavy_and_dirty = data.get('heavy_and_dirty', client_rate.heavy_and_dirty)
    client_rate.include_hnd_in_service_price = data.get('include_hnd_in_service_price', client_rate.include_hnd_in_service_price)
    client_rate.rates = data.get('rates', client_rate.rates)
    client_rate.comments = data.get('comments', client_rate.comments)

    # Commit changes to the database
    db.session.commit()

    return jsonify(client_rate.to_dict()), 200

# DELETE request to delete a client rate by rate_code
@app.route('/api/client_rate/<int:id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'editor'])
def delete_client_rate(id):
    # Fetch the client rate by rate_code
    client_rate = ClientRate.query.get_or_404(id)

    # Delete the record from the database
    db.session.delete(client_rate)
    db.session.commit()

    return jsonify({"message": "Client rate card deleted successfully"}), 200    


@app.route('/api/pn/<string:unique_id>', methods=['PUT'])
@jwt_required()
@role_required(['admin', 'editor'])
def update_pn(unique_id):
    """
    Update an existing Payment Notice (PN) entry
    ---
    tags:
      - Payment Notice
    security:
      - JWT: []
    parameters:
      - name: unique_id
        in: path
        type: string
        required: true
        description: The unique ID of the PN entry to update
      - name: body
        in: body
        required: true
        description: The fields to update
        schema:
          type: object
          properties:
            payment_notice_id:
              type: string
            contractor_afp_ref:
              type: string
            pn_date_issued_to_contractor:
              type: string
              format: date
            date_of_application:
              type: string
              format: date
            purchase_order_id:
              type: string
            region:
              type: string
            exchange_id:
              type: string
            town:
              type: string
            contractor:
              type: string
            polygon_type:
              type: string
            polygon_id:
              type: string
            feature_id:
              type: string
            build_status:
              type: string
            code:
              type: string
            item:
              type: string
            unit:
              type: string
            price:
              type: number
              format: decimal
            quantity:
              type: number
              format: decimal
            total:
              type: number
              format: decimal
            comments:
              type: string
            afp_claim_ok_nok:
              type: string
            nok_reason_code:
              type: string
            approved_quantity:
              type: number
              format: decimal
            approved_total:
              type: number
              format: decimal
            concate:
              type: string
            qgis_quant:
              type: number
              format: decimal
            qgis_rate:
              type: number
              format: decimal
            qgis_url:
              type: string
            po_check:
              type: string
            comment:
              type: string
    responses:
      200:
        description: Successfully updated
      400:
        description: Bad request - Invalid input or missing data
      401:
        description: Unauthorized - Invalid or missing token
      403:
        description: Forbidden - User does not have required role
      404:
        description: Not found - PN entry does not exist
      500:
        description: Internal server error
    """
    try:
        pn_entry = PnRaw.query.get(unique_id)
        if not pn_entry:
            return jsonify({'error': 'PN entry not found'}), 404

        data = request.json
        for key, value in data.items():
            if hasattr(pn_entry, key):
                setattr(pn_entry, key, value)

        db.session.commit()

        return jsonify({'message': 'PN entry updated successfully', 'data': pn_entry.to_dict()}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/logout', methods=['POST'])
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

def calculate_cost(seed, eod_item):
    ooh_rates = SubcontractorRate.query.filter_by(rate_code='OOH001').first()
    
    user_rev = UserRevenue.query.filter(func.lower(UserRevenue.user_name) == func.lower(eod_item.User_Name)).first()
    if not user_rev:
        return {"seed": seed, "error": f"User {eod_item.User_Name} not found in UserRevenue table"}
    
    revenue_generating_entity = user_rev.revenue_generating_entity

    if revenue_generating_entity.upper() == "SET":
        return {
            "cost": 0,
        }
    
    subcontractor_rate = SubcontractorRate.query.filter_by(rate_code=eod_item.Item_Mst_ID).first()
    if not subcontractor_rate:
        return {"seed": seed, "error": f"Rate not found for Item_Mst_ID: {eod_item.Item_Mst_ID}"}
    
    rate = getattr(subcontractor_rate, revenue_generating_entity.lower(), None)
    if rate is None:
        return {"seed": seed, "error": f"Rate not found for entity: {revenue_generating_entity}"}
    
    base_cost = float(eod_item.Qty) * float(rate)
    
    is_weekend = False
    weekend_rate = 0
    if eod_item.Date and eod_item.Date.weekday() >= 5:
        is_weekend = True
        weekend_rate = getattr(ooh_rates, revenue_generating_entity.lower(), 0)
        if weekend_rate:
            base_cost *= (1 + float(weekend_rate) / 100)
    
    return {
        "cost": base_cost + float(weekend_rate) if weekend_rate else base_cost,
    }



@app.route('/api/pn/sum_approved', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_pn_sum_approved():
    try:
        filters = request.args.to_dict()

        # Validate and set pagination parameters
        # limit = int(request.args.get('limit', 100))
        # page = int(request.args.get('page', 1))

        # Handle date range if provided
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
            end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
        else:
            # Default to last 30 days if no date range is provided
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)

        query = db.session.query(
            PnRaw.date_of_application,
            func.sum(PnRaw.approved_total).label('total_approved')
        ).filter(
            PnRaw.date_of_application.between(start_date, end_date)
        ).group_by(
            PnRaw.date_of_application
        )
        # Apply additional filters dynamically
        for key, value in filters.items():
            if key not in ['start_date', 'end_date'] and hasattr(PnRaw, key) and value:
                query = query.filter(getattr(PnRaw, key) == value)
        # total_records = query.with_entities(func.count(PnRaw.date_of_application)).scalar()
        # print(total_records)

        # Handle pagination
        # data = query.offset((page - 1) * limit).limit(limit).all()
        data=query.all()
        # Format the response
        aggregated_data = []
        for row in data:
            aggregated_data.append({
                'date': row.date_of_application.strftime('%d-%m-%Y'),
                'total_approved': float(row.total_approved)
            })

        response = {
            # 'total_records': total_records,
            # 'page': page,
            # 'per_page': limit,
            'data': aggregated_data
        }

        return jsonify(response), 200

    except ValueError:
        return jsonify({'error': 'Invalid input for limit or page'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/pn', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_pn():
    """
    Get Payment Notice (PN) Data
    ---
    tags:
      - Payment Notice
    security:
      - JWT: []
    parameters:
      - name: limit
        in: query
        type: integer
        default: 100
        description: Number of records to return per page
      - name: page
        in: query
        type: integer
        default: 1
        description: Page number
      - name: payment_notice_id
        in: query
        type: string
        description: Filter by payment notice ID
      - name: contractor_afp_ref
        in: query
        type: string
        description: Filter by contractor AFP reference
      - name: region
        in: query
        type: string
        description: Filter by region
      - name: contractor
        in: query
        type: string
        description: Filter by contractor
    responses:
      200:
        description: Successful response
        schema:
          type: object
          properties:
            total_records:
              type: integer
              description: Total number of records matching the query
            page:
              type: integer
              description: Current page number
            per_page:
              type: integer
              description: Number of records per page
            data:
              type: array
              items:
                type: object
                properties:
                  unique_id:
                    type: string
                  payment_notice_id:
                    type: string
                  contractor_afp_ref:
                    type: string
                  pn_date_issued_to_contractor:
                    type: string
                  date_of_application:
                    type: string
                  # Add other properties from PnRaw model here
      401:
        description: Unauthorized - Invalid or missing token
      403:
        description: Forbidden - User does not have required role
    """

    try:
        filters = request.args.to_dict()

        # Validate and set pagination parameters
        limit = int(request.args.get('limit', 100))
        page = int(request.args.get('page', 1))

        query = PnRaw.query

        # Apply filters dynamically
        for key, value in filters.items():
            if hasattr(PnRaw, key) and value:  # Check for non-empty values
                query = query.filter(getattr(PnRaw, key) == value)

        total_records = query.with_entities(func.count(PnRaw.unique_id)).scalar()
        print(total_records)
        data = query.offset((page - 1) * limit).limit(limit).all()

        response = {
            'total_records': total_records,
            'page': page,
            'per_page': limit,
            'data': [item.to_dict() for item in data]
        }

        return jsonify(response), 200

    except ValueError:
        return jsonify({'error': 'Invalid input for limit or page'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/api/subcontractor_rate', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_subcontractor_rates():
    # Extract query parameters
    filters = request.args.to_dict()

    # Build the query dynamically
    query = SubcontractorRate.query
    for key, value in filters.items():
        if hasattr(SubcontractorRate, key):
            query = query.filter(getattr(SubcontractorRate, key) == value)

    # Execute the query and get results
    results = query.all()

    # Convert results to dictionary
    results_dict = [result.to_dict() for result in results]

    return jsonify(results_dict), 200


@app.route('/api/client_rate', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_client_rates():
    # Extract query parameters
    filters = request.args.to_dict()

    # Build the query dynamically
    query = ClientRate.query
    for key, value in filters.items():
        if hasattr(ClientRate, key):
            query = query.filter(getattr(ClientRate, key) == value)

    # Execute the query and get results
    results = query.all()

    # Convert results to dictionary
    results_dict = [result.to_dict() for result in results]

    return jsonify(results_dict), 200


@app.route('/api/user_revenue', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_user_revenues():
    # Extract query parameters
    filters = request.args.to_dict()

    # Build the query dynamically
    query = UserRevenue.query
    for key, value in filters.items():
        if hasattr(UserRevenue, key):
            query = query.filter(getattr(UserRevenue, key) == value)

    # Execute the query and get results
    results = query.all()

    # Convert results to dictionary
    results_dict = [result.to_dict() for result in results]

    return jsonify(results_dict), 200    


def send_reset_email(to_email, reset_token):
    
    print(reset_token)
    # Gmail credentials
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    from_email = 'stlautomation123@gmail.com'
    password = 'thyuysdcdonpymsr'

    # Create the email content
    subject = 'Password Reset Request | XX Portal'
    body = f'''
    Hi,

    We received a request to reset your password. Click the link below to reset it:

    http://10.100.130.76:5000/reset_password?token={reset_token}

    If you did not request this, please ignore this email.

    Best regards,
    Team Automation
    gsb.automation@stl.tech
    '''

    # Create a MIMEText object and set up the email headers
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the Gmail SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()

        print('Email sent successfully')
    except Exception as e:
        print(f'Failed to send email: {e}')

# Update the forgot password API to use email_id
@app.route('/api/forgot_password', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
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
    send_reset_email(email_id, reset_token)

    return jsonify({'message': 'Password reset link has been sent'}), 200


# Update the reset password API to use email_id
@app.route('/api/reset_password', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
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
        email_id = jwt.decode_token(reset_token)['identity']
    except Exception as e:
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.filter_by(email_id=email_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    print("Password reset done")
    db.session.commit()

    return jsonify({'message': 'Password reset successfully'}), 200


@app.route('/api/add_subcontractor_rates', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def add_subcontractor_rates():
    data = request.get_json()
    
    if not isinstance(data, list):
        return jsonify({'error': 'Input data should be a list of entries'}), 400

    results = []
    for entry in data:
        required_fields = ['rate_code', 'work_category', 'rate_type', 'item', 'unit']
        missing_fields = [field for field in required_fields if field not in entry]
        
        if missing_fields:
            results.append({'success': False, 'missing_fields': missing_fields})
            continue

        subcontractor_rate = SubcontractorRate(
            rate_code=entry.get('rate_code'),
            work_category=entry.get('work_category'),
            rate_type=entry.get('rate_type'),
            item=entry.get('item'),
            unit=entry.get('unit'),
            heavy_and_dirty=entry.get('heavy_and_dirty'),
            include_hnd_in_service_price=entry.get('include_hnd_in_service_price'),
            description=entry.get('description'),
            afs=entry.get('afs'),
            bk_comms=entry.get('bk_comms'),
            ccg=entry.get('ccg'),
            jk_comms=entry.get('jk_comms'),
            jdc=entry.get('jdc'),
            jto=entry.get('jto'),
            nola=entry.get('nola'),
            rollo=entry.get('rollo'),
            salcs=entry.get('salcs'),
            upscale=entry.get('upscale'),
            vsl=entry.get('vsl'),
            vus=entry.get('vus')
        )
        
        db.session.add(subcontractor_rate)
        results.append({'success': True, 'data': subcontractor_rate.to_dict()})
    
    db.session.commit()

    return jsonify(results), 201


@app.route('/api/add_user_revenues', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def add_user_revenues():
    """
    Add User Revenues
    ---
    tags:
      - User Revenue
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: array
          items:
            type: object
            properties:
              user_name:
                type: string
                description: Username of the revenue-generating user.
                example: johndoe
              revenue_generating_entity:
                type: string
                description: Entity generating the revenue.
                example: Acme Corp
            required:
              - user_name
              - revenue_generating_entity
    responses:
      201:
        description: Successfully added user revenues.
        schema:
          type: array
          items:
            type: object
            properties:
              entry:
                type: object
                description: Original entry from the input.
              success:
                type: boolean
                description: Whether the entry was successfully processed.
              error:
                type: string
                description: Error message if the entry was not successful.
                nullable: true
            example:
              - entry:
                  user_name: johndoe
                  revenue_generating_entity: Acme Corp
                success: true
              - entry:
                  user_name: 
                  revenue_generating_entity: Acme Corp
                success: false
                error: Missing user_name
      400:
        description: Bad request - Input data should be a list of entries.
        schema:
          type: object
          properties:
            error:
              type: string
              example: Input data should be a list of entries
    security:
      - BearerAuth: []
    """


    data = request.get_json()
    
    if not isinstance(data, list):
        return jsonify({'error': 'Input data should be a list of entries'}), 400

    results = []
    user_revenues = []

    for entry in data:
        user_name = entry.get('user_name')
        revenue_generating_entity = entry.get('revenue_generating_entity')

        if not user_name:
            results.append({'entry': entry, 'success': False, 'error': 'Missing user_name'})
            continue

        if not revenue_generating_entity:
            results.append({'entry': entry, 'success': False, 'error': 'Missing revenue_generating_entity'})
            continue
        
        user_revenue = UserRevenue(user_name=user_name, revenue_generating_entity=revenue_generating_entity)
        user_revenues.append(user_revenue)
        results.append({'entry': entry, 'success': True})

    if user_revenues:
        db.session.bulk_save_objects(user_revenues)
        db.session.commit()

    return jsonify(results), 201 

@app.route('/api/login', methods=['POST'])
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

@app.route('/api/data', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_data():
    """
    Retrieve data
    ---
    tags:
      - Data
    security:
      - JWT: []
    parameters:
      - name: limit
        in: query
        type: integer
        default: 1000
      - name: page
        in: query
        type: integer
        default: 1
      - name: start_date
        in: query
        type: string
        format: date
      - name: end_date
        in: query
        type: string
        format: date
      - name: User_Name
        in: query
        type: string
      - name: Area
        in: query
        type: array
        items:
          type: string
    responses:
      200:
        description: Successful response
        schema:
          type: object
          properties:
            total_records:
              type: integer
            page:
              type: integer
            per_page:
              type: integer
            data:
              type: array
              items:
                type: object
                properties:
                  User_Name:
                    type: string
                  Date:
                    type: string
                    format: date
                  revenue_generating_entity:
                    type: string
                  category:
                    type: string
                  Area:
                    type: string
      401:
        description: Unauthorized
      403:
        description: Forbidden
    """
    filters = request.args.to_dict()

    limit = int(request.args.get('limit', 1000))  # Default to 1000 rows
    page = int(request.args.get('page', 1))  # Default to page 1

    query = EODDump.query.outerjoin(
        UserRevenue,
        func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)
    ).outerjoin(
        WorkCat,
        EODDump.Item_Mst_ID == WorkCat.Rate_Code
    )

    # Handle date range
    start_date = filters.get('start_date')
    end_date = filters.get('end_date')
    
    if start_date and end_date:
        start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
        end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
        query = query.filter(EODDump.Date.between(start_date, end_date))

    # Handle area and other comma-separated columns
    for key, value in filters.items():
        if hasattr(EODDump, key):
            if ',' in value:  # Check if there are multiple values separated by commas
                value_list = value.split(',')
                query = query.filter(getattr(EODDump, key).in_(value_list))
            else:
                query = query.filter(getattr(EODDump, key) == value)

    total_records = query.with_entities(func.count()).scalar()
    data = query.offset((page - 1) * limit).limit(limit).all()

    response_data = []
    for item in data:
        item_dict = item.to_dict()
        user_revenue = item.user_revenue
        work_cat = item.work_cat

        item_dict['revenue_generating_entity'] = user_revenue.revenue_generating_entity if user_revenue else None
        item_dict['category'] = work_cat.Category if work_cat else None    

        response_data.append(item_dict)

    response = {
        'total_records': total_records,
        'page': page,
        'per_page': limit,
        'data': response_data
    }

    return jsonify(response)


@app.route('/api/data/revenue', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_revenue_data():

    try:
        filters = request.args.to_dict()

        limit = int(request.args.get('limit', 1000))  # Default to 1000 rows
        page = int(request.args.get('page', 1))  # Default to page 1

        query = EODDump.query.outerjoin(
            UserRevenue,
            func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)
        ).outerjoin(
            WorkCat,
            EODDump.Item_Mst_ID == WorkCat.Rate_Code
        ).outerjoin(
            ClientRate,
            EODDump.Item_Mst_ID == ClientRate.rate_code
        )

        # Handle date range
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
            end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
            query = query.filter(EODDump.Date.between(start_date, end_date))

        # Handle area and other comma-separated columns
        for key, value in filters.items():
            if hasattr(EODDump, key):
                if ',' in value:  # Check if there are multiple values separated by commas
                    value_list = value.split(',')
                    query = query.filter(getattr(EODDump, key).in_(value_list))
                else:
                    query = query.filter(getattr(EODDump, key) == value)

        total_records = query.with_entities(func.count()).scalar()
        data = query.offset((page - 1) * limit).limit(limit).all()

        response_data = []
        for item in data:
            item_dict = item.to_dict()
            user_revenue = item.user_revenue
            work_cat = item.work_cat

            item_dict['revenue_generating_entity'] = user_revenue.revenue_generating_entity if user_revenue else None
            item_dict['category'] = work_cat.Category if work_cat else None

            # Calculate revenue
            revenue = db.session.query(
                func.sum(EODDump.Qty * ClientRate.rates)
            ).filter(
                EODDump.Seed == item.Seed
            ).scalar()
            
            item_dict['revenue'] = revenue if revenue is not None else 0
            
            # Calculate cost
            cost_data = calculate_cost(item.Seed, item)
            item_dict.update(cost_data)
            
            response_data.append(item_dict)

        response = {
            'total_records': total_records,
            'page': page,
            'per_page': limit,
            'data': response_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/data/aggregated_revenue', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_aggregated_revenue_data():
    try:
        filters = request.args.to_dict()

        # Handle date range
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
            end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
        else:
            # Default to last 30 days if no date range is provided
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)

        query = db.session.query(
            EODDump.Date,
            EODDump.Approved_Status,
            UserRevenue.revenue_generating_entity,
            func.sum(EODDump.Qty * ClientRate.rates).label('revenue'),
        ).join(
            UserRevenue,
            func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)       
        ).join(
            ClientRate,
            EODDump.Item_Mst_ID == ClientRate.rate_code
        ).filter(
            EODDump.Date.between(start_date, end_date)
        ).group_by(
            EODDump.Date,
            EODDump.Approved_Status,
            UserRevenue.revenue_generating_entity
        )

        # Apply additional filters
        for key, value in filters.items():
            if key not in ['start_date', 'end_date'] and hasattr(EODDump, key):
                query = query.filter(getattr(EODDump, key) == value)

        result = query.all()

        aggregated_data = []
        for row in result:
            # Categorize the approved_status
            if row.Approved_Status.lower() in ['approved']:
                status_category = 'approved'
            elif row.Approved_Status.lower() in ['rejected']:
                status_category = 'rejected'
            else:
                status_category = 'risk'

            aggregated_data.append({
                'date': row.Date.strftime('%d-%m-%Y'),
                'approved_status': status_category,
                'revenue_generating_entity': row.revenue_generating_entity,
                'revenue': float(row.revenue),
            })

        response = {
            'total_records': len(aggregated_data),
            'data': aggregated_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# @app.route('/api/data/sum_revenue', methods=['GET'])
# @jwt_required()
# @role_required(['admin', 'editor', 'viewer'])
# def get_sum_revenue_data():
#     try:
#         filters = request.args.to_dict()

#         # Handle date range
#         start_date = filters.get('start_date')
#         end_date = filters.get('end_date')

#         if start_date and end_date:
#             start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
#             end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
#         else:
#             # Default to last 30 days if no date range is provided
#             end_date = datetime.now().date()
#             start_date = end_date - timedelta(days=30)

#         query = db.session.query(
#             EODDump.Date,
#             func.sum(EODDump.Qty * ClientRate.rates).label('revenue'),
            
#         ).join(
#             UserRevenue,
#             func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)       
#         ).join(
#             ClientRate,
#             EODDump.Item_Mst_ID == ClientRate.rate_code
#         ).filter(
#             EODDump.Date.between(start_date, end_date)
#         ).group_by(
#             EODDump.Date       
#              )

#         # Apply additional filters
#         for key, value in filters.items():
#             if key not in ['start_date', 'end_date'] and hasattr(EODDump, key):
#                 query = query.filter(getattr(EODDump, key) == value)

#         result = query.all()

#         # aggregated_data = []
#         # ************
#         aggregated_data = []
#         for row in result:
#             # Categorize the approved_status
#             if row.Approved_Status.lower() in ['approved']:
#                 status_category = 'approved'
#             elif row.Approved_Status.lower() in ['rejected']:
#                 status_category = 'rejected'
#             else:
#                 status_category = 'risk'

#             aggregated_data.append({
#                 'date': row.Date.strftime('%d-%m-%Y'),
#                 'approved_status': status_category,
#                 'revenue_generating_entity': row.revenue_generating_entity,
#                 'revenue': float(row.revenue),
#             })

#         response = {
#             'total_records': len(aggregated_data),
#             'data': aggregated_data
#         }
#         # ************
#         # for row in result:
#         #     aggregated_data.append({
#         #         'date': row.Date.strftime('%d-%m-%Y'),
#         #         'revenue': float(row.revenue),
#         #     })

#         # response = {
#         #     'total_records': len(aggregated_data),
#         #     'data': aggregated_data
#         # }

#         return jsonify(response)

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@app.route('/api/data/sum_revenue', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_sum_revenue_data():
    try:
        filters = request.args.to_dict()

        # Handle date range
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
            end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
        else:
            # Default to last 30 days if no date range is provided
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)

        query = db.session.query(
            EODDump.Date,
            func.sum(EODDump.Qty * ClientRate.rates).label('revenue'),
            EODDump.Approved_Status
        ).join(
            UserRevenue,
            func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)       
        ).join(
            ClientRate,
            EODDump.Item_Mst_ID == ClientRate.rate_code
        ).filter(
            EODDump.Date.between(start_date, end_date)
        ).group_by(
            EODDump.Date,
            EODDump.Approved_Status
        )

        # Apply additional filters
        for key, value in filters.items():
            if key not in ['start_date', 'end_date', 'approved_status'] and hasattr(EODDump, key):
                query = query.filter(getattr(EODDump, key) == value)

        if 'approved_status' in filters:
            approved_status_filter = filters['approved_status'].lower()
            if approved_status_filter in ['approved', 'rejected']:
                query = query.filter(func.lower(EODDump.Approved_Status) == approved_status_filter)
            else:
                query = query.filter(~EODDump.Approved_Status.in_(['approved', 'rejected']))

        result = query.all()

        # Aggregate the data
        aggregated_data = []
        for row in result:
            # Categorize the approved_status
            if row.Approved_Status.lower() == 'approved':
                status_category = 'approved'
            elif row.Approved_Status.lower() == 'rejected':
                status_category = 'rejected'
            else:
                status_category = 'risk'

            aggregated_data.append({
                'date': row.Date.strftime('%d-%m-%Y'),
                'approved_status': status_category,
                'revenue': float(row.revenue),
            })

        response = {
            'total_records': len(aggregated_data),
            'data': aggregated_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/api/data/sum_cost', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor'])
def get_sum_cost_data():
    try:
        filters = request.args.to_dict()

        # Handle date range
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
            end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
        else:
            # Default to last 30 days if no date range is provided
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)

        query = db.session.query(
            EODDump.Date,
            func.sum(EODDump.Qty * SubcontractorRate.afs).label('cost_afs'),
            func.sum(EODDump.Qty * SubcontractorRate.bk_comms).label('cost_bk_comms'),
            func.sum(EODDump.Qty * SubcontractorRate.ccg).label('cost_ccg'),
            func.sum(EODDump.Qty * SubcontractorRate.jk_comms).label('cost_jk_comms'),
            func.sum(EODDump.Qty * SubcontractorRate.jdc).label('cost_jdc'),
            func.sum(EODDump.Qty * SubcontractorRate.jto).label('cost_jto'),
            func.sum(EODDump.Qty * SubcontractorRate.nola).label('cost_nola'),
            func.sum(EODDump.Qty * SubcontractorRate.rollo).label('cost_rollo'),
            func.sum(EODDump.Qty * SubcontractorRate.salcs).label('cost_salcs'),
            func.sum(EODDump.Qty * SubcontractorRate.upscale).label('cost_upscale'),
            func.sum(EODDump.Qty * SubcontractorRate.vsl).label('cost_vsl'),
            func.sum(EODDump.Qty * SubcontractorRate.vus).label('cost_vus'),
            func.sum(EODDump.Qty * SubcontractorRate.set).label('cost_set')
            
        ).join(
            WorkCat,
            func.lower(WorkCat.Rate_Code) == func.lower(EODDump.Item_Mst_ID)       
        ).join(
            SubcontractorRate,
            EODDump.Item_Mst_ID == SubcontractorRate.rate_code
        ).filter(
            EODDump.Date.between(start_date, end_date)
        ).group_by(
            EODDump.Date       
             )


        # Apply the 'Category' filter from the WorkCat table
        if 'Category' in filters:
            category_value = filters.get('Category')
            query = query.filter(WorkCat.Category == category_value)

        # Apply additional filters
        for key, value in filters.items():
            if key not in ['start_date', 'end_date'] and hasattr(EODDump, key):
                query = query.filter(getattr(EODDump, key) == value)

        result = query.all()

        aggregated_data = []
        for row in result:
            costs = [
                {'tag': 'afs', 'cost': float(row.cost_afs)},
                {'tag': 'bk_comms', 'cost': float(row.cost_bk_comms)},
                {'tag': 'ccg', 'cost': float(row.cost_ccg)},
                {'tag': 'jk_comms', 'cost': float(row.cost_jk_comms)},
                {'tag': 'jdc', 'cost': float(row.cost_jdc)},
                {'tag': 'jto', 'cost': float(row.cost_jto)},
                {'tag': 'nola', 'cost': float(row.cost_nola)},
                {'tag': 'rollo', 'cost': float(row.cost_rollo)},
                {'tag': 'salcs', 'cost': float(row.cost_salcs)},
                {'tag': 'upscale', 'cost': float(row.cost_upscale)},
                {'tag': 'vsl', 'cost': float(row.cost_vsl)},
                {'tag': 'vus', 'cost': float(row.cost_vus)},
                {'tag': 'set', 'cost': float(row.cost_set)}
            ]
            
            total_cost = sum(cost['cost'] for cost in costs)

            aggregated_data.append({
                'date': row.Date.strftime('%d-%m-%Y'),
                'costs': costs,
                'total_cost': total_cost
            })

        response = {
            'total_records': len(aggregated_data),
            'data': aggregated_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500







@app.route('/dashboard_data')
@jwt_required()
@role_required(['admin', 'editor'])
def dashboard_data():
    # Get all months with invoice data
    invoice_months = db.session.query(
        func.date_format(PnRaw.date_of_application, '%Y-%m').label('month'),
        func.sum(PnRaw.approved_total).label('total_invoice')
    ).group_by('month').all()

    result = []

    for invoice_month, total_invoice in invoice_months:
        month_data = {
            'month': invoice_month,
            'total_invoice': float(total_invoice),
            'total_revenue': 0,  # Initialize total_revenue
            'revenue_breakup': []
        }

        # Get revenue breakup for each month
        start_date = datetime.strptime(invoice_month, '%Y-%m')
        end_date = datetime(start_date.year, start_date.month, calendar.monthrange(start_date.year, start_date.month)[1])

        revenue_breakup = db.session.query(
            func.date_format(EODDump.Date, '%Y-%m').label('revenue_month'),
            func.sum(EODDump.Qty * ClientRate.rates).label('revenue')
        ).join(
            UserRevenue,
            func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)
        ).join(
            ClientRate,
            EODDump.Item_Mst_ID == ClientRate.rate_code
        ).join(
            PnRaw,
            PnRaw.seed == EODDump.Seed
        ).filter(
            PnRaw.date_of_application.between(start_date, end_date)
        ).group_by(
            'revenue_month'
        ).all()

        for revenue_month, revenue in revenue_breakup:
            month_data['revenue_breakup'].append({
                'month': revenue_month,
                'revenue': float(revenue)
            })
            month_data['total_revenue'] += float(revenue)  # Add to total_revenue

        result.append(month_data)

    return jsonify(result)




@app.route('/api/dashboard_data1', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor'])
def dashboard_data1():
    try:
        today = datetime.now()
        six_months_ago = today - timedelta(days=180)

        last_6_months_data = db.session.query(
            func.date_format(PnRaw.date_of_application, '%Y-%m').label('month'),
            func.sum(PnRaw.approved_total).label('total_invoice')
        ).filter(
            PnRaw.date_of_application >= six_months_ago
        ).group_by('month').all()

        older_months_data = db.session.query(
            func.date_format(PnRaw.date_of_application, '%Y-%m').label('month'),
            func.sum(PnRaw.approved_total).label('total_invoice')
        ).filter(
            PnRaw.date_of_application < six_months_ago
        ).group_by('month').all()

        def get_revenue_breakup(months_data):
            result = []
            aggregated_total_revenue=0
            aggregated_total_invoice=0

            for invoice_month, total_invoice in months_data:
                aggregated_revenue_old = 0
                aggregated_total_invoice += float(total_invoice)
                month_data = {
                    'month': invoice_month,
                    'total_invoice': float(total_invoice),
                    'total_revenue': 0,
                    'revenue_breakup': []
                }

                start_date = datetime.strptime(invoice_month, '%Y-%m')
                end_date = datetime(start_date.year, start_date.month, calendar.monthrange(start_date.year, start_date.month)[1])

                revenue_breakup = db.session.query(
                    func.date_format(EODDump.Date, '%Y-%m').label('revenue_month'),
                    func.sum(EODDump.Qty * ClientRate.rates).label('revenue')
                ).join(
                    UserRevenue,
                    func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)
                ).join(
                    ClientRate,
                    EODDump.Item_Mst_ID == ClientRate.rate_code
                ).join(
                    PnRaw,
                    PnRaw.seed == EODDump.Seed
                ).filter(
                    PnRaw.date_of_application.between(start_date, end_date)
                ).group_by(
                    'revenue_month'
                ).all()

                for revenue_month, revenue in revenue_breakup:
                    revenue = float(revenue)
                    if datetime.strptime(revenue_month, '%Y-%m') >= six_months_ago:
                        month_data['revenue_breakup'].append({
                            'month': revenue_month,
                            'revenue': revenue
                        })
                    else:
                        aggregated_revenue_old += revenue
                    month_data['total_revenue'] += revenue
                    aggregated_total_revenue += revenue

                month_data['revenue_breakup'].append({
                    'month': 'aggregated_revenue_old',
                    'revenue': aggregated_revenue_old
                })
                aggregated_revenue_old = 0
                result.append(month_data)

            result.append({
              'aggregated_total_revenue' : aggregated_total_revenue,
              'aggregated_total_invoice' : aggregated_total_invoice
            })    
            return result

        last_6_months_result = get_revenue_breakup(last_6_months_data)
        older_months_result = get_revenue_breakup(older_months_data)

        response = {
            'last_6_months': last_6_months_result,
            'older_months': older_months_result
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/manage_user', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def manage_user():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user:
        user.role = data.get('role', user.role)
        user.can_edit = data.get('can_edit', user.can_edit)
        db.session.commit()
        return jsonify({"success": True, "message": "User updated successfully"})
    return jsonify({"success": False, "message": "User not found"}), 404



# Read a single user by ID
@app.route('/api/users/<int:id>', methods=['GET'])
@jwt_required()
@role_required(['admin'])
def get_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email_id': user.email_id,
        'phone_no': user.phone_no,
        'role': user.role,
        'can_edit': user.can_edit
    }), 200


# Update a user
@app.route('/api/users/<int:id>', methods=['PUT'])
@jwt_required()
@role_required(['admin'])
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.json
    if 'username' in data:
        user.username = data['username']
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='sha256')
    if 'email_id' in data:
        user.email_id = data['email_id']
    if 'phone_no' in data:
        user.phone_no = data['phone_no']
    if 'role' in data:
        user.role = data['role']
    if 'can_edit' in data:
        user.can_edit = data['can_edit']

    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200


# Delete a user
@app.route('/api/users/<int:id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'editor'])
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200



@app.route('/api/users', methods=['GET'])
@jwt_required()
@role_required(['admin'])
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email_id': user.email_id,
        'phone_no': user.phone_no,
        'role': user.role,
        'can_edit': user.can_edit
    } for user in users]), 200




@app.route('/api/update_revenue_status', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
def update_revenue_status():
    data = request.json
    user = User.query.filter_by(email_id=get_jwt_identity()).first()

    if not user.can_edit:
        return jsonify({"success": False, "message": "You don't have edit rights"}), 403

    for item in data['items']:
        eod_item = EODDump.query.get(item['seed'])
        if eod_item:
            eod_item.Taken_To_Revenue = item['Taken_To_Revenue']
            eod_item.Taken_To_Revenue_Date = datetime.now() # Update the date
            log = ActivityLog(user_id=user.id, action=f"Updated Taken_To_Revenue for seed {item['seed']} to {item['Taken_To_Revenue']}")
            db.session.add(log)

    db.session.commit()
    return jsonify({"success": True})






@app.route('/api/upload', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
def upload_file():
    
    """
    Upload Payment Notice Excel File
    ---
    tags:
      - File Upload
    security:
      - JWT: []
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: Excel file containing Payment Notice data
    responses:
      200:
        description: File uploaded and data stored/updated successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: File uploaded and data stored/updated successfully
      400:
        description: Bad request - No file or no selected file
        schema:
          type: object
          properties:
            error:
              type: string
              example: No file part
      401:
        description: Unauthorized - Invalid or missing token
      403:
        description: Forbidden - User does not have required role
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            error:
              type: string
              example: An error occurred while processing the file
    
    """
    column_mapping = {
        "Unique ID": "unique_id",
        "Payment Notice ID": "payment_notice_id",
        "Contractor AFP ref": "contractor_afp_ref",
        "PN date Issued to Contractor": "pn_date_issued_to_contractor",
        "Date of Application": "date_of_application",
        "Purchase Order ID": "purchase_order_id",
        "Region": "region",
        "Exchange ID": "exchange_id",
        "Town": "town",
        "Contractor": "contractor",
        "Polygon Type": "polygon_type",
        "Polygon ID": "polygon_id",
        "Feature ID": "feature_id",
        "Build Status": "build_status",
        "code": "code",
        "item": "item",
        "unit": "unit",
        "price": "price",
        "quantity": "quantity",
        "total": "total",
        "Comments": "comments",
        "AfP Claim OK / NOK": "afp_claim_ok_nok",
        "NOK Reason Code": "nok_reason_code",
        "Approved Quantity": "approved_quantity",
        "Approved Total": "approved_total",
        "CONCATE": "concate",
        "QGIS Quant": "qgis_quant",
        "QGIS Rate": "qgis_rate",
        "QGIS URL": "qgis_url",
        "PO Check": "po_check",
        "Comment": "comment"
    }

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        # Read the Excel file into a DataFrame
        df = pd.read_excel(file, skiprows=5, usecols="B:AF")
        df = df.replace({np.nan: None})

        df.rename(columns=column_mapping, inplace=True)
        count=df.shape[0]

        # Loop through the DataFrame and upsert (update or insert) each row
        for index, row in df.iterrows():
            unique_id = row['unique_id']
            existing_entry = db.session.query(PnRaw).filter_by(unique_id=unique_id).first()
            
            if existing_entry:
                # Update the existing entry
                for key, value in row.items():
                    setattr(existing_entry, key, value)
                db.session.commit()
            else:
                # Insert new entry
                new_entry = PnRaw(**row)
                db.session.add(new_entry)
                db.session.commit()

        return jsonify({'message': f'File uploaded and data stored/updated successfully, inserted {count} rows'}), 200
    except Exception as e:
        db.session.rollback()  # Rollback in case of any error
        return jsonify({'error': str(e)}), 500



@app.route('/api/unique_values', methods=['GET'])
@jwt_required()
def get_unique_values():
    table_name = request.args.get('table')
    column_name = request.args.get('column')

    if not table_name or not column_name:
        return jsonify({"error": "Both 'table' and 'column' parameters are required"}), 400

    try:
        # Reflect the table from the database
        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=db.engine)

        # Check if the column exists in the table
        if column_name not in table.columns:
            return jsonify({"error": f"Column '{column_name}' does not exist in table '{table_name}'"}), 404

        # Query for unique values
        query = select(table.columns[column_name]).distinct()
        result = db.session.execute(query)
        unique_values = [value[0] for value in result.fetchall()]

        return jsonify({"unique_values": unique_values})

    except Exception as e:
        return jsonify({"error": str(e)}), 500




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email_id='admin@gmail.com').first():
            admin = User(username='admin', password=bcrypt.generate_password_hash('adminpass').decode('utf-8'), role='admin', can_edit=True)
            editor = User(username='editor', password=bcrypt.generate_password_hash('editorpass').decode('utf-8'), role='editor', can_edit=True)
            viewer = User(username='viewer', password=bcrypt.generate_password_hash('viewerpass').decode('utf-8'), role='viewer', can_edit=False)
            db.session.add_all([admin, editor, viewer])
            db.session.commit()
    app.run(host='0.0.0.0', port=5001,debug=True)


