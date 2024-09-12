from flask import Blueprint
from models import *
from flask import Flask, request, jsonify
from conf import app, db, engine, swagger, bcrypt, jwt, migrate, swagger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from utils import role_required
from helper_func import *


pn_blueprint = Blueprint('pn', __name__)

CORS(app)

@pn_blueprint.route('/testsss')
def home():
    return "pn Test"



@pn_blueprint.route('/pn', methods=['GET'])
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




@pn_blueprint.route('pn/<string:unique_id>', methods=['PUT'])
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




@pn_blueprint.route('/pn_raw/<unique_id>', methods=['DELETE'])
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
