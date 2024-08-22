# create_tables.py

from app import app, db

# Run the database creation inside the application context
with app.app_context():
    db.create_all()
    print("Tables created successfully!")
