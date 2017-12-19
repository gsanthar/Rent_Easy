from application import db
from application.models import User, Product, Bid

db.create_all()

print("DB created.")

