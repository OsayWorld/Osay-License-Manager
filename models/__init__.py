from extensions import db
from models.user import User

# Function to initialize the database models
def init_db():
    db.create_all()  # Create all the tables if they don't exist
