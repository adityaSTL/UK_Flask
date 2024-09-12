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
from helper_func import *

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


# CORS(app)
# swagger = Swagger(app)





bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)


engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])




