from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import DECIMAL
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from functools import wraps
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request

app = Flask(__name__)
CORS(app)

db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_name = os.getenv('DB_NAME')

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqldb://root:Admin%40123@10.100.130.76/eod"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', '1234567890') # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)





class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime)


class WorkCat(db.Model):
    __tablename__ = 'work_cat'
    Rate_Code = db.Column(db.String(255), primary_key=True)
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
    afs_ltd = db.Column(db.DECIMAL(10, 2), nullable=True)
    bk_comms = db.Column(db.DECIMAL(10, 2), nullable=True)
    ccg = db.Column(db.DECIMAL(10, 2), nullable=True)
    jk_comm = db.Column(db.DECIMAL(10, 2), nullable=True)
    jdc = db.Column(db.DECIMAL(10, 2), nullable=True)
    jto = db.Column(db.DECIMAL(10, 2), nullable=True)
    nola = db.Column(db.DECIMAL(10, 2), nullable=True)
    rollo = db.Column(db.DECIMAL(10, 2), nullable=True)
    salcs = db.Column(db.DECIMAL(10, 2), nullable=True)
    upscale = db.Column(db.DECIMAL(10, 2), nullable=True)
    vsl = db.Column(db.DECIMAL(10, 2), nullable=True)
    vus = db.Column(db.DECIMAL(10, 2), nullable=True)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}



class ClientRate(db.Model):
    __tablename__ = 'client_rate'
    rate_code = db.Column(db.String(50), primary_key=True)
    rate_type = db.Column(db.String(255))
    item = db.Column(db.String(255))
    unit = db.Column(db.String(50))
    heavy_and_dirty = db.Column(db.String(25))
    include_hnd_in_service_price = db.Column(db.String(25))
    rates = db.Column(db.String(255))
    comments = db.Column(db.String(255))


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

@app.route('/api/add_user_revenues', methods=['POST'])
def add_user_revenues():
    data = request.get_json()
    
    if not isinstance(data, list):
        return jsonify({'error': 'Input data should be a list of entries'}), 400

    user_revenues = []
    for entry in data:
        user_name = entry.get('user_name')
        revenue_generating_entity = entry.get('revenue_generating_entity')
        
        if not user_name or not revenue_generating_entity:
            return jsonify({'error': 'Each entry must have user_name and revenue_generating_entity'}), 400
        
        user_revenue = UserRevenue(user_name=user_name, revenue_generating_entity=revenue_generating_entity)
        user_revenues.append(user_revenue)
    
    db.session.bulk_save_objects(user_revenues)
    db.session.commit()

    return jsonify([user_revenue.to_dict() for user_revenue in user_revenues]), 201

# Role-Based Access Control Decorator
def role_required(roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if current_user.role not in roles:
                return jsonify({"msg": "Unauthorized access"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper


# API Endpoints
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token, role=user.role, can_edit=user.can_edit), 200
    return jsonify({"msg": "Bad username or password"}), 401


@app.route('/api/data', methods=['GET'])
def get_data():
    filters = request.args.to_dict()

    limit = int(request.args.get('limit', 100))  # Default to 100 rows
    query = EODDump.query

    for key, value in filters.items():
        if hasattr(EODDump, key):
            query = query.filter(getattr(EODDump, key) == value)

    data = query.limit(limit).all()
    # data = query.all()
    return jsonify([item.to_dict() for item in data])


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


@app.route('/api/update_revenue_status', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
def update_revenue_status():
    data = request.json
    user = User.query.filter_by(username=get_jwt_identity()).first()

    if not user.can_edit:
        return jsonify({"success": False, "message": "You don't have edit rights"}), 403

    for item in data['items']:
        eod_item = EODDump.query.get(item['seed'])
        if eod_item:
            eod_item.Taken_To_Revenue = item['Taken_To_Revenue']
            log = ActivityLog(user_id=user.id, action=f"Updated Taken_To_Revenue for seed {item['seed']} to {item['Taken_To_Revenue']}")
            db.session.add(log)

    db.session.commit()
    return jsonify({"success": True})



@app.route('/api/get_revenue', methods=['POST'])
@jwt_required()
@role_required(['admin', 'viewer', 'editor'])
def get_revenue():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    print(user)

    data = request.json
    print("Received data:", data)  # Debug statement
    seeds = data.get('Seeds')
    
    if not seeds or not isinstance(seeds, list):
        return jsonify({"success": False, "message": "Seeds parameter is required and must be a list"}), 400
    
    try:
        revenue_results = {}
        for seed in seeds:
            total_revenue = db.session.query(
                db.func.sum(EODDump.Qty * ClientRate.rates)
            ).join(
                ClientRate, EODDump.Item_Mst_ID == ClientRate.rate_code
            ).filter(
                EODDump.Seed == seed
            ).scalar()
            
            revenue_results[seed] = total_revenue if total_revenue is not None else 0
        
        return jsonify({"success": True, "revenue": revenue_results})
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=bcrypt.generate_password_hash('adminpass').decode('utf-8'), role='admin', can_edit=True)
            editor = User(username='editor', password=bcrypt.generate_password_hash('editorpass').decode('utf-8'), role='editor', can_edit=True)
            viewer = User(username='viewer', password=bcrypt.generate_password_hash('viewerpass').decode('utf-8'), role='viewer', can_edit=False)
            db.session.add_all([admin, editor, viewer])
            db.session.commit()
    app.run(host='0.0.0.0', port=5000)


