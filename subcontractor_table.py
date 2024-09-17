from flask import Blueprint
from models import *
from flask import Flask, request, jsonify
from conf import app, db, engine, swagger, bcrypt, jwt, migrate, swagger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from utils import role_required
from helper_func import *


subcontractor_blueprint = Blueprint('subcontractor', __name__)

CORS(app)

@subcontractor_blueprint.route('/testss')
def home():
    return "subcontractor Test"


#Get list of all clients

@subcontractor_blueprint.route('/subcontractor_rate', methods=['GET'])
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




#Adding a new subcontractor card
@subcontractor_blueprint.route('/subcontractor_rate', methods=['POST'])
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



# PUT request to update an existing subcontractor rate
@subcontractor_blueprint.route('/subcontractor_rate/<int:id>', methods=['PUT'])
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
@subcontractor_blueprint.route('/subcontractor_rate/<int:id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'editor'])
def delete_subcontractor_rate(id):
    # Fetch the subcontractor rate by ID
    subcontractor_rate = SubcontractorRate.query.get_or_404(id)

    # Delete the record from the database
    db.session.delete(subcontractor_rate)
    db.session.commit()

    return jsonify({"message": "Subcontractor rate card deleted successfully"}), 200    