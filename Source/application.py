from flask import Flask, session, render_template, redirect, url_for, request, flash, json, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug import generate_password_hash, check_password_hash, secure_filename
from datetime import date, datetime
from flask.ext.login import LoginManager
import datetime as dt
from application import db
from application.models import User, Product, Bid, Booking, Bookqueue
from flask_socketio import SocketIO, send, emit, join_room, leave_room, rooms, close_room
import functools
from flask_socketio import disconnect
from sqlalchemy import or_, and_
from datetime import datetime, timedelta, date
from flask_mail import Mail, Message
from application.rent_token  import generate_confirmation_token, cancel_token
from sqlalchemy import desc
from collections import defaultdict
import os
import shutil


async_mode = None

application = Flask(__name__)
mail=Mail(application)

application.secret_key = "super secret key"
application.config["DEBUG"] = True

application.config['MAIL_SERVER']='smtp.gmail.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_USERNAME'] = 'rentingsystem@gmail.com'
application.config['MAIL_PASSWORD'] = 'GaSa2016'
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
mail = Mail(application)

# Flask Login
login_manager = LoginManager()
login_manager.init_app(application)
socketio = SocketIO(application, async_mode=async_mode)
thread = None
user_found = 1
owner_act = 2

d_q = defaultdict(list)

IMG_FOLDER = 'static/img/'
application.config['IMG_FOLDER'] = IMG_FOLDER


def th_func():
        p_state = Product()
        print('Testing product')
        query_state = p_state.query.order_by(p_state.id).all()
        for index in range(len(query_state)):
            print(query_state[index].get_id())
            bid_status = query_state[index].get_bid_status()
            if bid_status == "bidding expired":
               announced = query_state[index].get_sold()
               print(announced)
               if not announced:
                      high_bid = query_state[index].get_highest_bid()
                      if not (high_bid is None):
                         user_high = User.query.filter_by(id = high_bid.get_bidder()).first()
                         username_high = user_high.first_name
                         print('username is', username_high)
                         product_high = query_state[index].get_title()
                         print('product is', product_high)
                         socketio.emit('my_response',
                         {'data': 'Auction Closed', 'cnt':'for', 'product': product_high, 'wnr':'And the Winner is', 'winner':username_high},
                         broadcast = True,namespace='/test')
                         #query_state[index].sold = 1
                         #db.session.commit()


    

def background_thread():
    """Example of how to send server generated events to clients."""
    count = 0
    while True:
        socketio.sleep(100)
        th_func()
        #socketio.emit('my_res', {'data': 'Connected'})

@application.before_request
def before_request():
    g.user = current_user


@login_manager.user_loader
def load_user(id):
    '''method used by Flask-Login to get
    key for login user. query.get is for primary keys'''
    return User.query.get(int(id))




def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped

'''
@socketio.on('connect', namespace='/test')
def test_connect():
     print ("connection call")
     #console.log('a user connected');
     emit('my response', {'data': 'Connected'})

#    if current_user.is_authenticated:
#         emit('my response', {'data': 'Connected'})
#    else:
#         return False
'''
@socketio.on('connect', namespace='/test')
def test_connect():
#    global thread
#    if thread is None:
#        thread = socketio.start_background_task(target=background_thread)
    if current_user.is_authenticated:
        user_room = 'user_{}'.format(session['user_id'])
        join_room(user_room)
        emit('my_response', {'data': 'Connected', 'count': 0})

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected',request.sid)


@socketio.on('my_event', namespace='/test')
def test_msg(message):
    th_func()
    print('Socket id is %s',message['data'])

@authenticated_only
def test_message():
    socketio.emit('my response', {'data': 'You are connected'}, broadcast=True, namespace='/test')
    #emit('new_msg', {msg: 'hello'},broadcast=True);


@socketio.on('send_message')
def handle_source(json_data):
    text = json_data['message'].encode('ascii', 'ignore')
    socketio.emit('myrespone', {'echo': 'Server Says: '+text})


@application.route('/')
def main():
    #return 'Hello ganesh from Flask!'
    p_shw = Product()
    query_shw = p_shw.query.order_by(desc(Product.id)).limit(3).all()
    if 'user_id' in session:
        user = User.query.filter_by(id = session['user_id']).first()
        username_session = user.username
        firstname_session = user.first_name
        lastname_session = user.last_name
        email_session = user.email
        return render_template('index.html', obj=query_shw,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session) 
    return render_template('index.html', obj=query_shw)

@application.route('/showSignUp')
def showSignUp():
    return render_template('signup.html')

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender='rentingsystem@gmail.com'
    )
    mail.send(msg)


@application.route('/search',methods=['POST','GET'])
def search_results():
    p_shw = Product()
    s_name = 'display all items'
    query_shw = p_shw.query.all()
    if 'user_id' in session:
        user = User.query.filter_by(id = session['user_id']).first()
        username_session = user.username
        firstname_session = user.first_name
        lastname_session = user.last_name
        email_session = user.email
    if request.method == 'POST':
        p_shw = Product()
	s_name = request.form['inputSearch']
	s_name = str(s_name)
        sl_name = s_name.split()
        print "names:",sl_name
        query_str_shw = p_shw.query.filter(or_(Product.title.ilike(s_name),Product.title.contains(s_name),Product.product_type.ilike(s_name),Product.product_type.contains(s_name))).all()
        print "search_str=",s_name
        print "query_output",query_str_shw
        if 'user_id' in session:
            user = User.query.filter_by(id = session['user_id']).first()
            username_session = user.username
            firstname_session = user.first_name
            lastname_session = user.last_name
            email_session = user.email
            return render_template('search.html', obj=query_str_shw,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session,obj_src=s_name)
        return render_template('search.html',obj=query_str_shw,obj_src=s_name)

    return render_template('search.html', obj=query_shw,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session,obj_src=s_name)


@application.route('/login' ,methods=['POST','GET'])
def login():
    if 'user_id' in session:
        user = User.query.filter_by(id = session['user_id']).first()
        username_session = user.username
        return render_template('index.html', session_user_name=username_session)
    if request.method == 'POST':
        try:
            name = request.form['inputName']
            password = request.form['inputPassword']
            curr_url = request.form['current_url']
            test_url = curr_url[-6:]
            print "current_url=",curr_url,test_url
	

            # validate the received values
            if name and password:
                    u = User.query.filter_by(username = name.lower()).first()
                    if not u:
                        flash('Username not right: Try Again')
                        if test_url in ['search']:
                           return redirect(url_for('search_results'))
                        else:
                           return redirect(url_for('main'))
                    if not u.check_password(password):
                        flash('Password not right: Try Again')
                        if test_url in ['search']:
                           return redirect(url_for('search_results'))
                        else:
                           return redirect(url_for('main'))

                    else:
                        user = User.query.filter_by(username = name.lower()).first()
                        login_user(user)
                        user.last_login = datetime.utcnow()
                        user.increment_login()
                        session['user_id'] = user.id
                        db.session.add(user)
                        db.session.commit()
                        test_message()
                        msg = "Welcome TO Renteasy  %s ." % user.first_name
                        flash(msg)
                        if test_url in ['search']:
                           return redirect(url_for('search_results'))
                        else:
                           return redirect(url_for('main'))

            else:
                flash('Enter all the Required Fields')
                if test_url in ['search']:
                   return redirect(url_for('search_results'))
                else:
                   return redirect(url_for('main'))


        except Exception as e:
            return json.dumps({'error':str(e)})


    if test_url in ['search']:
       return redirect(url_for('search_results'))
    else:
       return redirect(url_for('main'))

    #return render_template('index.html')


def test_user():
    global user_found
    uid = session['user_id']
    p_state = Product()
    query_state = p_state.query.order_by(p_state.id).all()
    for index in range(len(query_state)):
        bid_status = query_state[index].get_bid_status()
        if bid_status != "bidding expired":
           usr_act = query_state[index].get_owner()
           if uid == usr_act:
              user_found += 1
              print(user_found)
           bids_act = query_state[index].get_all_bids()
           for indx in range(len(bids_act)):
               print('bidder:',bids_act[indx].buyer_id)
               if uid == bids_act[indx].buyer_id:
                  user_found += 1
               else:
                   user_found = 1
                   print('user not found')
        else:
            print('no active bids')





@login_required
@application.route('/products' ,methods=['POST','GET'])
def products():
    p_shw = Product()
    query_p_all = p_shw.query.order_by(desc(Product.id)).limit(3).all()
    user = User.query.filter_by(id = session['user_id']).first()
    username_session = user.username
    firstname_session = user.first_name
    lastname_session = user.last_name
    email_session = user.email

    if request.method == 'POST':
        try:
            pname = request.form['inputPname']
            ptype = request.form['inputPtype']
            pdesc = request.form['inputPdesc']
            sprice = request.form['inputSprice']
            ppic = request.files['inputPpic']
            paddr = user.user_addr + "," + user.user_city
            owner = user.get_id()           
            print "saleprice=",sprice
            if pname and ptype and sprice :
                    p = Product(
                            owner_id = owner,
                            title = pname,
                            sale_price = sprice,
                            product_type = ptype,
                            product_desc = pdesc,
                            product_addr = paddr
                            )

                    db.session.add(p)
                    db.session.commit()
                    p_suc = Product()
                    query_suc = p_suc.query.filter(and_((Product.title == pname),(Product.sale_price == sprice))).all()
                    user = User.query.filter_by(id = session['user_id']).first()
                    username_session = user.username
                    firstname_session = user.first_name
                    lastname_session = user.last_name
                    email_session = user.email
                    query_p_all = p_suc.query.order_by(desc(Product.id)).limit(3).all()


		    if ppic:
		       ppic_fname = secure_filename(ppic.filename)
                       pic_name = 'img_'+ str(p.id) +'.jpg'
		       print "if case filename",ppic_fname,pic_name
                       ppic.save(ppic_fname)
                       os.rename(ppic_fname,pic_name)
		       print "if case filename",ppic_fname,pic_name
                       dst_dir= os.path.join(os.curdir , "static/img/")
                       src_file = os.path.join(os.curdir, pic_name)
                       shutil.move(src_file,dst_dir)
		       print "if case filename",pic_name,src_file
		    else:
		       ppic_fname = 'img.jpg'
                       pic_name = 'img_'+ str(p.id) +'.jpg'
                       os.rename(ppic_fname,pic_name)
		       cwd = os.getcwd()
                       dst_dir = os.path.join(cwd,application.config['IMG_FOLDER'])
                       src_file = os.path.join(os.curdir, pic_name)
                       shutil.copy(src_file,dst_dir)
                       os.rename(pic_name,'img.jpg')
		       print "else case filename",pic_name
                    return render_template('products.html',obj=query_suc,obj_all=query_p_all, session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
            else:
                flash('Enter all the Required Fields')
                user = User.query.filter_by(id = session['user_id']).first()
                username_session = user.username
                firstname_session = user.first_name
                lastname_session = user.last_name
                email_session = user.email
                p_fail = Product()
                query_p_all = p_fail.query.order_by(desc(Product.id)).limit(3).all()

                return render_template('products.html',obj_all=query_p_all,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)

        except Exception as e:
            return json.dumps({'error':str(e)})

                
    return render_template('products.html',obj_all=query_p_all,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
    #return render_template('products.html')

@login_required
@application.route('/bids' ,methods=['POST','GET'])
def bids():
    p_bids = Product()
    query_bids = p_bids.query.order_by(p_bids.owner_id).all()
    user_bids = User.query.filter_by(id = session['user_id']).first()
    username_session = user_bids.username
    if request.method == 'POST':
        try:
            bptype = request.form['inputBptype']
            bprice = request.form['inputBprice']
            owner = user_bids.get_id()           
            if bptype and bprice:
                    b = Bid(
                            bidder = owner,
                            product = bptype,
                            bid_price = bprice,
                            )

                    db.session.add(b)
                    db.session.commit()
                    msg = "New bid added."
                    flash(msg)
                    p_fbid = Product()
                    query_fbid = p_fbid.query.order_by(p_fbid.owner_id).all()
                    user = User.query.filter_by(id = session['user_id']).first()
                    username_session = user.username
                    firstname_session = user.first_name
                    lastname_session = user.last_name
                    email_session = user.email
                    return render_template('products.html',obj=query_fbid,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
            else:
                flash('Enter all the Required Fields')
                p_sid = Product()
                query_sid = p_sid.query.order_by(p_sid.owner_id).all()
                user = User.query.filter_by(id = session['user_id']).first()
                username_session = user.username
                firstname_session = user.first_name
                lastname_session = user.last_name
                email_session = user.email
                return render_template('products.html',obj=query_sid,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)

        except Exception as e:
            return json.dumps({'error':str(e)})

    return render_template('products.html',obj=query_bids,session_user_name=username_session)


@login_required
@application.route('/cancel/<token>')
def cancel_email(token):
    try:
        email_token = cancel_token(token)
    except:
        flash('The cancellation link is invalid or has expired.', 'danger')
    email, bid = email_token.split(',')
    all_book = Booking()
    user_bids = User.query.filter(User.email == email).first()
    booktoc = all_book.query.filter(and_(Booking.buyer_id == user_bids.id, Booking.id == int(bid))).all()
    if not booktoc:
        flash('Booking already cancelled. Thank you')
    else:
        books_to_del = all_book.query.filter(Booking.id == bid).first()
        p_all = Product()
        p_sel = p_all.query.filter(Product.id == books_to_del.product_id).first()
        bid_title = p_sel.title
        bq_bk = p_sel.get_highest_queue()
        bq_all = Bookqueue()
        #bq_sel = bq_all.query.filter(Bookqueue.p_id == books_to_del.product_id).first()
        
        if bq_bk:
           all_book.query.filter(Booking.id == bid).delete()
           q_fr = bq_bk.get_booked_from()
           q_to = bq_bk.get_booked_to()
           q_uid = bq_bk.get_userid()
           q_pid = books_to_del.product_id
           q_m_fr = str(q_fr)
           q_m_fr = datetime.strftime(q_fr, "%m-%d-%Y %H:%M:%S")
           q_m_to = str(q_to)
           q_m_to = datetime.strftime(q_to, "%m-%d-%Y %H:%M:%S")
           usr_q = User.query.filter(User.id == q_pid).first()
           b = Booking(
                   bidder = q_uid,
                   product = q_pid,
                   booked_from = q_m_fr,
                   booked_to = q_m_to
                   )
           db.session.add(b)
           bq_all.query.filter(Bookqueue.id == bq_bk.id).delete()
           db.session.commit()
           email_token = usr_q.email + "," + str(b.id)
           token = generate_confirmation_token(email_token)
           cancel_url = url_for('cancel_email', token=token, _external=True)
           html = render_template('book_cancel.html', cancel_url=cancel_url,obj_ptitle=p_sel.title,obj_pprice=p_sel.sale_price,session_user_name=usr_q.username,session_first_name=usr_q.firstname,session_last_name=usr_q.lastname,session_email=usr_q.email,bookfrom=l_fr,bookto=l_to)
           subject = "Your Booking Info"
           send_email(user.email, subject, html)
           msg = "You cancelled your Booking with id:",str(bid),"with Title:",str(bid_title)
           flash(msg)
           return redirect(url_for('main'))
        
        else:   
           all_book.query.filter(Booking.id == bid).delete()
           db.session.commit()
           msg = "You have Successfully cancelled your Booking with id:",str(bid),"with Title:",str(bid_title)
           flash(msg)
           return redirect(url_for('main'))
    return redirect(url_for('main'))


def verify_date(fr_dt,to_dt,fdt,tdt):
    if fr_dt <= datetime.strptime(fdt, "%m-%d-%Y %H:%M:%S") <= to_dt or fr_dt <= datetime.strptime(tdt, "%m-%d-%Y %H:%M:%S") <= to_dt:
       return False
    return True    
            


def add_d_q(fr,to,b_pid,uid):
    bqtest = Bookqueue()
    bq_query = bqtest.query.filter(and_(Bookqueue.p_id == b_pid,Bookqueue.user_id == uid)).all()
    if bq_query:
       return False
    else: 
       bq = Bookqueue(
                user_id = uid,
                p_id = b_pid,
                booked_from = fr,
                booked_to = to
                )
       db.session.add(bq)
       db.session.commit()
       return True


@login_required
@application.route('/book_queue' ,methods=['POST','GET'])
def book_queue():
    p_bids = Product()
    if request.method == 'POST':
       if request.form['inputaddqueue'] == 'Yes':
          p_bids = Product()
          usr_bids = User.query.filter_by(id = session['user_id']).first()
          username_session = usr_bids.username
          firstname_session = usr_bids.first_name
          lastname_session = usr_bids.last_name
          email_session = usr_bids.email
          #ibook_from = request.form['ibooked_from']
          #ibook_to = request.form['ibooked_to']
          ibook_from = "12-14-2017 00:00:00"
          ibook_to = "12-15-2017 00:00:00"
          ibook_id = request.form['ibooked_pid']
          query_q_fbid = p_bids.query.filter_by(id = ibook_id).first()
          query_p_all = p_bids.query.order_by(desc(Product.id)).limit(3).all()
          res_add_q = add_d_q(ibook_from,ibook_to,ibook_id,usr_bids.id)
          p_str = "As requested you have been added to the queue of the below item"
          if res_add_q:
             return render_template('booking.html',obj_str=p_str,obj_all=query_p_all,book_q_from = ibook_from,book_q_to=ibook_to,book_st = False,obj_pid=query_q_fbid.id,obj_ptype=query_q_fbid.product_type,obj_ptitle=query_q_fbid.title,obj_pprice=query_q_fbid.sale_price,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
          else:
             p_str = "Sorry, you already in the queue of the below item"
             return render_template('booking.html',obj_str=p_str,obj_all=query_p_all,book_q_from = ibook_from,book_q_to=ibook_to,book_st = False,obj_pid=query_q_fbid.id,obj_ptype=query_q_fbid.product_type,obj_ptitle=query_q_fbid.title,obj_pprice=query_q_fbid.sale_price,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
        
       elif request.form['inputaddqueue'] == 'No':
          return redirect(url_for('main'))
    return redirect(url_for('main'))


                
@login_required
@application.route('/book' ,methods=['POST','GET'])
def book():
    p_bids = Product()
    user_bids = User.query.filter_by(id = session['user_id']).first()
    query_p_all = p_bids.query.order_by(desc(Product.id)).limit(3).all()
    username_session = user_bids.username
    if request.method == 'POST':
        try:
            bpid = request.form['bookId']
            bfrom = request.form['date1']
            bto = request.form['date2']
            user_book = User.query.filter_by(id = session['user_id']).first()
            owner = user_book.get_id()
            test_bfrom = str(bfrom)
            test_bto = str(bto)
            bfrom = test_bfrom.replace("/","-")
            bfrom = bfrom + " 00:00:00"           
            bto = test_bto.replace("/","-")           
            bto = bto + " 00:00:00"
            bk_all = Booking()           
            bk_list = bk_all.query.filter(Booking.product_id == bpid).all()
            if bk_list:
               for index in range(len(bk_list)):
                  booked_from = bk_list[index].get_booked_from()
                  booked_to = bk_list[index].get_booked_to()
                  res_dt = verify_date(booked_from,booked_to,bfrom,bto)
                  print "Result of verify_date:",res_dt
                  if not res_dt:
                     delta = datetime.strptime(bto, "%m-%d-%Y %H:%M:%S") - datetime.strptime(bfrom, "%m-%d-%Y %H:%M:%S")
                     al_date = bk_list[index].getmaxtodate() 
                     delta_1 = timedelta(days=1)
                     al_date_fm = al_date.booked_to + delta_1
                     al_date_to = al_date_fm + delta
                     p_al_bid = Product()
                     query_al_fbid = p_al_bid.query.filter_by(id = bpid).first()
                     user = User.query.filter_by(id = session['user_id']).first()
                     username_session = user.username
                     firstname_session = user.first_name
                     lastname_session = user.last_name
                     email_session = user.email
                     if query_al_fbid:
                        print "inside query_al_fbid:",query_al_fbid.product_type
                        query_sim = p_al_bid.query.filter(Product.product_type == query_al_fbid.product_type).all()
                        print "inside query_al_fbid:",query_al_fbid.product_type
                        if query_sim:
                           print "inside query_al_fbid:",query_al_fbid.product_type
                           return render_template('booking.html',obj_1=query_sim,bookfrom=bfrom,bookto=bto,ibookpid=bpid,bookalfrom = al_date_fm,bookalto=al_date_to,book_st = False,obj_pid=query_al_fbid.id,obj_ptype=query_al_fbid.product_type,obj_ptitle=query_al_fbid.title,obj_pprice=query_al_fbid.sale_price,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
                        else:
                           query_p_all = p_al_bid.query.order_by(desc(Product.id)).limit(3).all()
                           return render_template('booking.html',obj_all=query_all,bookfrom=bfrom,bookto=bto,ibookpid=bpid,bookalfrom = al_date_fm,bookalto=al_date_to,book_st = False,obj_pid=query_al_fbid.id,obj_ptype=query_al_fbid.product_type,obj_ptitle=query_al_fbid.title,obj_pprice=query_al_fbid.sale_price,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
                     return render_template('booking.html',bookfrom=bfrom,bookto=bto,ibookpid=bpid,bookalfrom = al_date_fm,bookalto=al_date_to,book_st = False,obj_pid=query_al_fbid.id,obj_ptype=query_al_fbid.product_type,obj_ptitle=query_al_fbid.title,obj_pprice=query_al_fbid.sale_price,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)

            
            print "product id:",bpid
            if bpid and bfrom and bto:
                    b = Booking(
                            bidder = owner,
                            product = bpid,
                            booked_from = bfrom,
                            booked_to = bto
                            )

                    db.session.add(b)
                    db.session.commit()
                    p_fbid = Product()
                    query_fbid = p_fbid.query.filter_by(id = bpid).first()
                    user = User.query.filter_by(id = session['user_id']).first()
                    username_session = user.username
                    firstname_session = user.first_name
                    lastname_session = user.last_name
                    email_session = user.email
                  
                    email_token = email_session + "," + str(b.id)
                    token = generate_confirmation_token(email_token)
                    cancel_url = url_for('cancel_email', token=token, _external=True)
                    html = render_template('book_cancel.html', cancel_url=cancel_url,obj_ptitle=query_fbid.title,obj_pprice=query_fbid.sale_price,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session,bookfrom=bfrom,bookto=bto)
                    subject = "Your Booking Info"
                    send_email(user.email, subject, html)
 
                    return render_template('booking.html',bookfrom = bfrom,bookto=bto,book_st = True,obj_pid=query_fbid.id,obj_ptitle=query_fbid.title,obj_pprice=query_fbid.sale_price,obj_ptype=query_fbid.product_type,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)
            else:
                p_sid = Product()
                query_sid = p_sid.query.filter_by(id = bpid).first()
                user = User.query.filter_by(id = session['user_id']).first()
                username_session = user.username
                firstname_session = user.first_name
                lastname_session = user.last_name
                email_session = user.email
                return render_template('booking.html',obj_pid=query_fbid.id,obj_ptitle=query_fbid.title,obj_pprice=query_fbid.sale_price,obj_ptype=query_fbid.product_type,session_user_name=username_session,session_first_name=firstname_session,session_last_name=lastname_session,session_email=email_session)

        except Exception as e:
            return json.dumps({'error':str(e)})

    return redirect(url_for('main'))

@application.route('/Register',methods=['POST','GET'])
def Register():
    if request.method == 'POST':
        try:
            fname = request.form['inputFName']
            lname = request.form['inputLName']
            uname = request.form['inputUName']
            email = request.form['inputEmail']
            password = request.form['inputPassword']
            addr = request.form['avenue']
            zcode = request.form['zipcode']
            city = request.form['city']


            # validate the received values
            if fname and lname and uname and email and password:

                email_check = User.query.filter_by(email = email.lower()).first()
                username_check = User.query.filter_by(username = uname.lower()).first()
                if username_check:
                    flash('Entered Username already taken,try a different one')
                    return redirect(url_for('main'))
                if email_check:
                    flash('Entered Email already taken,try a different one')
                    return redirect(url_for('main'))

                else:

                    u = User(
                            username = uname,
                            first_name = fname,
                            last_name = lname,
                            email = email,
                            password = password,
                            user_addr = addr,
                            user_zcode = zcode,
                            user_city = city
                            )

                    db.session.add(u)
                    db.session.commit()
                    msg = "New User %s created." % fname
                    flash(msg)
                    return redirect(url_for('main'))

            else:
                flash('Enter all the Required Fields')
                return redirect(url_for('main'))

        except Exception as e:
            return json.dumps({'error':str(e)})

    return redirect(url_for('main'))


@application.route('/logout', methods=['GET'])
@login_required
def logout():
    '''
    This function signs the user out of the system
    '''
    global user_found
    #test_user()
    print(user_found)
    user = User.query.filter_by(id = session['user_id']).first()
    if user_found > 1:
       user_found = 1
       msg = "User %s Active in a bid." % user.first_name
       flash(msg)
       return redirect(url_for('products'))
    else:
       # put user_id in session for later use
       # delete session created during login
       del session['user_id']
       user.last_logout = datetime.utcnow()
       db.session.commit()
       logout_user()
       msg = "%s Logged out." % user.first_name
       flash(msg)
       return redirect(url_for('main'))




if __name__ == "__main__":
    from gevent import monkey
    monkey.patch_all()
    application.debug = True
    #application.run(host='0.0.0.0')
    socketio.run(application,host='0.0.0.0')
