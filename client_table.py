from flask import Blueprint
from models import *
from flask import Flask, request, jsonify
from conf import app, db, engine, swagger, bcrypt, jwt, migrate, swagger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from utils import role_required
from helper_func import *



client_blueprint = Blueprint('client', __name__)

CORS(app)


@client_blueprint.route('/tests')
def home():
    return "Client Test"


#Get list of all clients
@client_blueprint.route('/client_rate', methods=['GET'])
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



#Adding a new client
@client_blueprint.route('/client_rate', methods=['POST'])
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



# PUT request to update an existing client rate
@client_blueprint.route('/client_rate/<int:id>', methods=['PUT'])
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
@client_blueprint.route('/client_rate/<int:id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'editor'])
def delete_client_rate(id):
    # Fetch the client rate by rate_code
    client_rate = ClientRate.query.get_or_404(id)

    # Delete the record from the database
    db.session.delete(client_rate)
    db.session.commit()

    return jsonify({"message": "Client rate card deleted successfully"}), 200    

