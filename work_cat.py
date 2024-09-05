# from app3 import work_cat
from models import *
from flask import Blueprint
from datetime import datetime, timedelta
import os



# Define a blueprint
other_bp = Blueprint('other_bp', __name__)

@other_bp.route('/route1')
def route1():
    return 'This is route 1 in another file.'

@other_bp.route('/route2')
def route2():
    return 'This is route 2 in another file.'




# @app.route('/api/work_cat', methods=['GET'])
# @jwt_required()
# @role_required(['admin', 'editor', 'viewer'])
# def get_work_cats():
#     # Extract query parameters
#     filters = request.args.to_dict()

#     # Build the query dynamically
#     query = WorkCat.query
#     for key, value in filters.items():
#         if hasattr(WorkCat, key):
#             query = query.filter(getattr(WorkCat, key) == value)

#     # Execute the query and get results
#     results = query.all()

#     # Convert results to dictionary
#     results_dict = [result.to_dict() for result in results]

#     return jsonify(results_dict), 200




# # PUT request to update an existing work category record
# @app.route('/api/work_cat/<string:rate_code>', methods=['PUT'])
# def update_work_cat(rate_code):
#     # Fetch the work category by Rate_Code
#     work_cat = WorkCat.query.get_or_404(rate_code)

#     # Get the data from the request
#     data = request.json

#     # Update fields if they are provided in the request
#     work_cat.Category = data.get('Category', work_cat.Category)

#     # Commit changes to the database
#     db.session.commit()

#     return jsonify(work_cat.to_dict()), 200


# # DELETE request to delete a work category record by Rate_Code
# @app.route('/api/work_cat/<string:rate_code>', methods=['DELETE'])
# def delete_work_cat(rate_code):
#     # Fetch the work category by Rate_Code
#     work_cat = WorkCat.query.get_or_404(rate_code)

#     # Delete the record from the database
#     db.session.delete(work_cat)
#     db.session.commit()

#     return jsonify({"message": "Work category deleted successfully"}), 200