# user_revenue.py

from flask import jsonify, request
from flask_jwt_extended import jwt_required
from app import db, role_required  # Import db and role_required from your main app

class UserRevenue(db.Model):
    __tablename__ = 'user_revenue'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(255), nullable=False)
    revenue_generating_entity = db.Column(db.String(255), nullable=False)

    def __init__(self, user_name, revenue_generating_entity):
        self.user_name = user_name
        self.revenue_generating_entity = revenue_generating_entity

    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'revenue_generating_entity': self.revenue_generating_entity
        }

def add_user_revenue():
    data = request.json
    new_user_revenue = UserRevenue(
        user_name=data['user_name'],
        revenue_generating_entity=data['revenue_generating_entity']
    )
    db.session.add(new_user_revenue)
    db.session.commit()
    return jsonify({"success": True, "message": "User revenue link added successfully"})

def get_user_revenue():
    user_revenues = UserRevenue.query.all()
    return jsonify([user_rev.to_dict() for user_rev in user_revenues])

def update_user_revenue(id):
    user_revenue = UserRevenue.query.get(id)
    if not user_revenue:
        return jsonify({"success": False, "message": "User revenue link not found"}), 404
    
    data = request.json
    user_revenue.user_name = data.get('user_name', user_revenue.user_name)
    user_revenue.revenue_generating_entity = data.get('revenue_generating_entity', user_revenue.revenue_generating_entity)
    
    db.session.commit()
    return jsonify({"success": True, "message": "User revenue link updated successfully"})

def delete_user_revenue(id):
    user_revenue = UserRevenue.query.get(id)
    if not user_revenue:
        return jsonify({"success": False, "message": "User revenue link not found"}), 404
    
    db.session.delete(user_revenue)
    db.session.commit()
    return jsonify({"success": True, "message": "User revenue link deleted successfully"})

def init_user_revenue():
    if not UserRevenue.query.first():
        initial_data = [
            ("ABHIJITH JAYACHITHRA", "SET"),
            ("AMALKUMAR KALIYANTHANATH SUKUMARAN", "SET"),
            ("ARUN JANARDAN", "SET"),
            ("ARUN SUNNY", "SET"),
            ("ASHIKH MUTTUMPURAM", "SET"),
            ("ASHISH CHAUHAN", "SET"),
            ("BASIL GEORGE", "SET"),
            ("BEN BAKER", "JK Comms"),
            ("BHARATH KUMAR KUPPUSAMY", "SET"),
            ("CHIRANJEET SHARMA", "N/A"),
            ("DEEPAK KUMAR SHUKLA", "SET"),
            ("DILBAG SINGH", "SET"),
            ("GANESHLAL SHRIVASTAV", "SET")
        ]
        
        for user_name, entity in initial_data:
            new_user_revenue = UserRevenue(user_name=user_name, revenue_generating_entity=entity)
            db.session.add(new_user_revenue)
        
        db.session.commit()