from application import db
from flask import Flask, session, render_template, redirect, url_for, request, flash, json, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug import generate_password_hash, check_password_hash
from datetime import date, datetime
from flask.ext.login import LoginManager
import datetime as dt
from sqlalchemy import desc
from sqlalchemy import or_



class User(db.Model):
    """This table is used to store User model in the database.
    One User has MANY Book
    One User has MANY Book_Complaints
    One User has MANY Book_Comments
    One User has MANY Book_Ratings
    One User has MANY Bids

    """
    __tablename__ = 'tbl_user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), unique=True, nullable=False)
    user_addr = db.Column(db.String(1024))
    user_city = db.Column(db.String(256))
    user_zcode = db.Column(db.String(256))
    pwdhash = db.Column(db.String(100))
    num_bookings = db.Column(db.Integer, default=0)
    num_purchases = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime)
    last_logout = db.Column(db.DateTime)
    num_logins = db.Column(db.Integer, default = 0)
    products = db.relationship('Product', backref='owner', lazy='dynamic')
    bookings = db.relationship('Booking', backref='bidder', lazy='dynamic')

    def __init__(self, username, first_name, last_name, email, password, user_addr, user_city, user_zcode):
        self.username = username
        self.first_name = first_name.title()
        self.last_name = last_name.title()
        self.email = email.lower()
        self.set_password(password)
        self.user_addr = user_addr
        self.user_city = user_city
        self.user_zcode = user_zcode

    def set_password(self, password):
        """This method generates SHA-1 string from given input, password."""
        self.pwdhash = generate_password_hash(password)

    def check_password(self, password):
        """This method compares generated SHA-1 Hash to hash in database."""
        return check_password_hash(self.pwdhash, password)

    def increment_login(self):
        """increments User login_count"""
        self.num_logins += 1

    def is_active(self):
        return True

    def get_id(self):
        """returns User's primary key id."""
        return str(self.id)
    
    def get_user_addr(self):
        """returns User's address."""
        return str(self.user_addr)

    def get_user_city(self):
        """returns User's city."""
        return str(self.user_city)

    def get_user_zcode(self):
        """returns User's Postal code."""
        return str(self.user_zcode)

    def is_authenticated(self):
        """returns False when Users are not logged in."""
        return True



class Product(db.Model):
    """  """
    __tablename__ = "tbl_product"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('tbl_user.id'), nullable=False)
    title = db.Column(db.String(256))
    product_type = db.Column(db.String(256))
    product_desc = db.Column(db.String(1024))
    product_addr = db.Column(db.String(1024))
    product_pic = db.Column(db.String(256))
    sale_price = db.Column(db.Float)
    date_added = db.Column(db.DateTime)
    bookings = db.relationship('Booking', backref='product', lazy='dynamic')


    def get_owner(self):
        return self.owner_id

    def get_id(self):
        return self.id

    def get_title(self):
        return self.title

    def get_producttype(self):
        return self.product_type

    def get_product_desc(self):
        return self.product_desc

    def get_product_pic(self):
        return self.product_pic

    def get_product_addr(self):
        return self.product_addr
    
    def get_sale_price(self):
        return self.sale_price

    def get_date_added(self):
        return self.date_added

    def get_expr_date(self):
        """return date when book should run out of time.
        Assuming that saleDuration is in minutes. """
        return self.date_added + dt.timedelta(minutes = self.saleDuration)


    def until_expire_in_mins(self):
        """returns time until book expires in minutes"""
        expr_date = self.get_expr_date()
        delta = expr_date - datetime.utcnow()
        delta_in_mins = int(delta.total_seconds() / 60 )
        return delta_in_mins

    def until_expire_in_hrs(self):
        """returns time until book expires in hours"""
        return (self.until_expire_in_mins() / 60)

    def get_bid_status(self):
        state = self.until_expire_in_mins()
        if state > 0:
            status = "Expires in" + str(state) + "minutes"
            return str(status)
        else:
            biddable = False
            return str('bidding expired')

    def get_highest_bid(self):
        """returns bid object with highest bid amount for book."""
        bid = Bid.query.filter_by(product_id=self.id).order_by(desc(Bid.bid_price)).first()
        return bid

    def get_all_bookings(self):
        """returns bid object with highest bid amount for book."""
        booking = Booking.query.filter_by(product_id=self.id).order_by(desc(Bid.booked_on)).all()
        return booking

    def get_highest_queue(self):
        """returns bid object with highest bid amount for book."""
        bqueue = Bookqueue.query.filter_by(p_id=self.id).order_by(desc(Bookqueue.booked_on)).first()
        return bqueue



    def __init__(self, title=None, sale_price=None, product_type=None, 
            product_desc=None,product_pic=None,date_added=None, owner_id=None,product_addr=None):
        '''init method. so this only runs during the creation of product object.'''
        self.title = title
        self.product_type = product_type
        self.product_desc = product_desc
        self.product_addr = product_addr
        self.product_pic = product_pic
        self.sale_price = sale_price
        # force starting_bid to be current_bid
        self.date_added = datetime.utcnow()
        self.owner_id = owner_id






class Bid(db.Model):
    """Table used to track ALL bids created for ALL books."""
    __tablename__ = "bid"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('tbl_product.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('tbl_user.id'), nullable=False)
    timestamp = db.Column(db.DateTime)
    bid_price = db.Column(db.Float, nullable=False)
    
    def get_bidder(self):
        return self.buyer_id


    def __init__(self, product, bidder, bid_price):
        self.buyer_id = bidder
        self.product_id = product
        self.bid_price = bid_price
        self.timestamp = datetime.utcnow()



class Booking(db.Model):
    """Table used to track ALL bookings created for ALL books."""
    __tablename__ = "booking"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('tbl_product.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('tbl_user.id'), nullable=False)
    booked_on = db.Column(db.DateTime)
    booked_from = db.Column(db.DateTime)
    booked_to = db.Column(db.DateTime)
    
    def get_bidder(self):
        return self.buyer_id


    def __init__(self, product=None, bidder=None, booked_from=None, booked_to=None):
        self.buyer_id = bidder
        self.product_id = product
        self.booked_on = datetime.utcnow()
        if booked_from and booked_to:
            self.booked_from = datetime.strptime(booked_from, "%m-%d-%Y %H:%M:%S")
            self.booked_to = datetime.strptime(booked_to, "%m-%d-%Y %H:%M:%S")
        else:
            self.booked_from = datetime.utcnow()
            self.booked_to = datetime.utcnow()
    

    def get_booked_from(self):
        """returns booked from date for a Booking Object."""
        return self.booked_from
    
    def get_booked_to(self):
        """returns booked to date for a Booking Object."""
        return self.booked_to


    def getmaxtodate(self):
        book = Booking.query.order_by(desc(Booking.booked_to)).first()
        return book

class Bookqueue(db.Model):
    """Table used to track ALL book queues created for ALL books."""
    __tablename__ = "bookqueue"
    id = db.Column(db.Integer, primary_key=True)
    p_id = db.Column(db.Integer, db.ForeignKey('tbl_product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_user.id'), nullable=False)
    booked_on = db.Column(db.DateTime)
    booked_from = db.Column(db.DateTime)
    booked_to = db.Column(db.DateTime)
    
    def get_userid(self):
        return self.user_id


    def __init__(self, p_id=None, user_id=None, booked_from=None, booked_to=None):
        self.user_id = user_id
        self.p_id = p_id
        self.booked_on = datetime.utcnow()
        if booked_from and booked_to:
            self.booked_from = datetime.strptime(booked_from, "%m-%d-%Y %H:%M:%S")
            self.booked_to = datetime.strptime(booked_to, "%m-%d-%Y %H:%M:%S")
        else:
            self.booked_from = datetime.utcnow()
            self.booked_to = datetime.utcnow()
    

    def get_booked_from(self):
        """returns booked from date for a Booking Object."""
        return self.booked_from
    
    def get_booked_to(self):
        """returns booked to date for a Booking Object."""
        return self.booked_to


