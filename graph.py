
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
from cachetools import TTLCache
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from flask_jwt_extended import decode_token


from flask import Blueprint
from models import *
from flask import Flask, request, jsonify
from conf import app, db, engine, swagger, bcrypt, jwt, migrate, swagger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from utils import role_required
from helper_func import *
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from flask_jwt_extended import decode_token


graph_blueprint = Blueprint('graph', __name__)

CORS(app)

@graph_blueprint.route('/testssss')
def home():
    return "graph Test"

@graph_blueprint.route('/sum_revenue', methods=['GET'])
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
            start_date = end_date - timedelta(days=300)

        # Query to fetch and aggregate revenue by month and approved status using DATE_FORMAT for MySQL
        query = db.session.query(
            func.date_format(EODDump.Date, '%Y-%m').label('month'),  # MySQL DATE_FORMAT
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
            func.date_format(EODDump.Date, '%Y-%m'),  # Group by month
            EODDump.Approved_Status
        )

        # Apply additional filters if needed
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

        # Organize data into a dictionary by month
        monthwise_data = {}
        for row in result:
            month = row.month
            status_category = 'risk'  # Default to risk unless it's explicitly approved or rejected
            if row.Approved_Status.lower() == 'approved':
                status_category = 'approved'
            elif row.Approved_Status.lower() == 'rejected':
                status_category = 'rejected'

            if month not in monthwise_data:
                monthwise_data[month] = {'approved': 0, 'rejected': 0, 'risk': 0}

            monthwise_data[month][status_category] += float(row.revenue)

        # Format the response
        aggregated_data = [{'month': month, 'approved': data['approved'], 'rejected': data['rejected'], 'risk': data['risk']}
                           for month, data in monthwise_data.items()]

        response = {
            'total_records': len(aggregated_data),
            'data': aggregated_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@graph_blueprint.route('/sum_revenue_all', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_sum_revenue_data_all():
    try:
        filters = request.args.to_dict()

        # Handle date range
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, "%d-%m-%Y").date()
            end_date = datetime.strptime(end_date, "%d-%m-%Y").date()
        else:
            # Default to last 300 days if no date range is provided
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=300)

        # Query to fetch and aggregate revenue by month and work category
        query = db.session.query(
            func.date_format(EODDump.Date, '%Y-%m').label('month'),  # MySQL DATE_FORMAT for year-month
            func.sum(EODDump.Qty * ClientRate.rates).label('revenue'),
            WorkCat.Category
        ).join(
            UserRevenue,
            func.lower(UserRevenue.user_name) == func.lower(EODDump.User_Name)
        ).join(
            ClientRate,
            EODDump.Item_Mst_ID == ClientRate.rate_code
        ).join(
            WorkCat,
            EODDump.Item_Mst_ID == WorkCat.Rate_Code
        ).filter(
            EODDump.Date.between(start_date, end_date)
        ).group_by(
            func.date_format(EODDump.Date, '%Y-%m'),  # Group by month
            WorkCat.Category  # Group by work category
        )

        # Apply additional filters if needed
        for key, value in filters.items():
            if key not in ['start_date', 'end_date'] and hasattr(EODDump, key):
                query = query.filter(getattr(EODDump, key) == value)

        result = query.all()

        # Organize data into a dictionary by month
        monthwise_data = {}
        for row in result:
            month = row.month
            # Handle NoneType for Category, default to 'unknown' if necessary
            category = row.Category.lower() if row.Category else 'unknown'  # Work category: 'civil', 'flex', or 'unknown'

            if month not in monthwise_data:
                monthwise_data[month] = {'civils': 0, 'flex': 0, 'unknown': 0}

            monthwise_data[month][category] += float(row.revenue)

        # Format the response
        aggregated_data = [{'month': month, 'civil': data['civils'], 'flex': data['flex'], 'unknown': data['unknown']}
                           for month, data in monthwise_data.items()]

        response = {
            'total_records': len(aggregated_data),
            'data': aggregated_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

