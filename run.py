from conf import app,db
from models import *
from users_mngt import users_blueprint
from client_table import client_blueprint
from subcontractor_table import subcontractor_blueprint
from pn_table import pn_blueprint
from app4 import app4_blueprint
from graph import graph_blueprint

app.register_blueprint(users_blueprint,url_prefix='/api')
app.register_blueprint(client_blueprint,url_prefix='/api')

app.register_blueprint(subcontractor_blueprint,url_prefix='/api')
app.register_blueprint(pn_blueprint,url_prefix='/api')

app.register_blueprint(graph_blueprint,url_prefix='/api')

app.register_blueprint(app4_blueprint)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email_id='admin@gmail.com').first():
            admin = User(username='admin', password=bcrypt.generate_password_hash('adminpass').decode('utf-8'), role='admin', can_edit=True)
            editor = User(username='editor', password=bcrypt.generate_password_hash('editorpass').decode('utf-8'), role='editor', can_edit=True)
            viewer = User(username='viewer', password=bcrypt.generate_password_hash('viewerpass').decode('utf-8'), role='viewer', can_edit=False)
            db.session.add_all([admin, editor, viewer])
            db.session.commit()
    app.run(host='0.0.0.0', port=5001,debug=True)
