import os

SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{username}:{password}@{hostname}/{databasename}".format(
    username="root",
    password="root",
    hostname="localhost",
    databasename="ebid",
)

UPLOAD_FOLDER = '/static/img'
SQLALCHEMY_POOL_RECYCLE = 3600
