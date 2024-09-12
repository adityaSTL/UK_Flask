

from flask import Blueprint
from models import *
from conf import *

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import DECIMAL

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

from conf import app, db, engine, swagger, bcrypt, jwt, migrate, swagger