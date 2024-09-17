
from datetime import datetime, timedelta
from flask_cors import CORS
from sqlalchemy import DECIMAL
from sqlalchemy.orm import relationship, foreign, remote
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from conf import db
from sqlalchemy import func
from sqlalchemy import inspect
from helper_func import format_date





class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email_id = db.Column(db.String(120), unique=True, nullable=False)
    phone_no = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(255), nullable=False) #-- This stores the image file path
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # name = db.Column(db.String(100), default=False)
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email_id": self.email_id,
            "phone_no": self.phone_no,
            "role": self.role,
            "can_edit": self.can_edit,
            "profile_image": self.profile_image,
            "created_at": format_date(self.created_at),  # Format the date before returning it
            "updated_at": format_date(self.updated_at)   # Format the date before returning it
        }


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
        """Convert the SQLAlchemy object to a dictionary with formatted date fields."""
        data = {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}

        # Format date fields using format_date function
        for date_field in ['pn_date_issued_to_contractor', 'date_of_application']:
            data[date_field] = format_date(data.get(date_field))

        return data    


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
        
        # Format date fields using format_date function
        result['Date'] = format_date(self.Date)
        result['Taken_To_Revenue_Date'] = format_date(self.Taken_To_Revenue_Date)

        return result




