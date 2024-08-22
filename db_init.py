
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)



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

