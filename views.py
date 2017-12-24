#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for
from flask import make_response, jsonify
from flask import session as login_session
from models import Base, CatalogCategory, User, Item, InitTable
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import random
import string


# Create session and connect to DB
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
session_factory = sessionmaker(bind=engine)
session = scoped_session(session_factory)
CLIENT_ID = (
    json.loads(open('client_secrets.json', 'r').read())['web']['client_id'])
app = Flask(__name__)


@app.route('/init_catalog')
def init_catalog():
    # Initialize the database
    init = session.query(InitTable).first()
    if init is not None and init.initialized:
        return redirect(url_for('main_page'))
    else:
        # Add a user to database
        user0 = User(id='0', name='user0', email='user0@gmail.com')
        session.add(user0)
        session.commit()

        # Add categories to database
        categories = [
            'Soccer', 'Basketball', 'Baseball',
            'Frisball', 'Snowboarding', 'Rock Climbing',
            'Foosball', 'Skating', 'Hockey']
        for category in categories:
            category = CatalogCategory(name=category)
            session.add(category)
        session.commit()

        # Add an item to database
        test_cat_id = session.query(CatalogCategory).filter_by(
            name='Snowboarding').one().id
        test_item = Item(title='Snowboard1', description='Test1',
                         cat_id=test_cat_id, user_id=user0.id)
        session.add(test_item)
        test_item = Item(title='Snowboard2', description='Test2',
                         cat_id=test_cat_id, user_id=user0.id)
        session.add(test_item)

        # Set initialized to true
        init = InitTable(initialized=True)
        session.add(init)
        session.commit()

        return redirect(url_for('main_page'))


@app.route('/login')
def show_login():
    # Create anti-forgery state token for login
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits
        ) for x in range(32)
    )
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/catalog/405')
def redirect_login():
    # Create redirect for the login page
    return render_template('redirectlogin.html')


def create_user(login_session):
    # User registration
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_ID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(
            json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode('utf8'))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = get_user_ID(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (
        ' " style="width: 300px; height: 300px;border-radius: 150px;'
        '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> ')
    print("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    # Log out of google
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps(
            'Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@app.route('/catalog/<string:name>/items')
def main_page(name=None):
    # Get category names
    categories = session.query(CatalogCategory).all()
    cat_name = (
        lambda cat_id:
        session.query(CatalogCategory).filter_by(id=cat_id).one().name)

    # Get latest added items
    latest_items = (
        session.query(Item).order_by(desc('created_datetime'))[0:9])

    # Get category items
    cat_items = []
    if name:
        cat_id = (
            session.query(CatalogCategory).filter_by(name=name).one().id)
        cat_items = session.query(Item).filter_by(cat_id=cat_id).all()

    if 'username' not in login_session:
        return render_template(
            'publiccatalog.html', categories=categories,
            name=name, latest_items=latest_items, cat_name=cat_name,
            cat_items=cat_items, len=len, content_header='publicheader')
    else:
        return render_template(
            'catalog.html', categories=categories,
            name=name, latest_items=latest_items, cat_name=cat_name,
            cat_items=cat_items, len=len)


@app.route('/catalog/<string:cat_name>/<int:item_id>')
def get_item(cat_name, item_id):
    # Get single item of a category and render to the page
    item = session.query(Item).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return render_template('publicitempage.html', item=item)
    else:
        return render_template(
            'itempage.html', item=item,
            cat_name=cat_name)


@app.route('/catalog', methods=['GET', 'POST'])
def add_item():
    # Handle add-item request
    if 'username' not in login_session:
        return redirect(url_for('show_login'))
    else:
        if request.method == 'POST':
            new_item = Item(
                title=request.form['title'],
                description=request.form['description'],
                cat_id=int(request.form['category']),
                user_id=login_session['user_id']
            )
            session.add(new_item)
            session.commit()
            return redirect(url_for('main_page'))
        else:
            categories = session.query(CatalogCategory).all()
            return render_template(
                'additempage.html',
                categories=categories)


@app.route(
    '/catalog/<string:cat_name>/<int:item_id>/edit',
    methods=['GET', 'POST'])
def edit_item(cat_name, item_id):
    # Handle edit-item request
    item = session.query(Item).filter_by(id=item_id).one()
    creator = get_user_info(item.user_id)
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return redirect(url_for('redirect_login'))
    else:
        if request.method == 'POST':
            item.title = request.form['title']
            item.description = request.form['description']
            item.cat_id = int(request.form['category'])
            session.add(item)
            session.commit()
            return redirect(
                url_for('get_item', cat_name=cat_name, item_id=item.id))
        else:
            categories = session.query(CatalogCategory).all()
            return render_template(
                'edititempage.html',
                categories=categories, item=item, cat_name=cat_name)


@app.route(
    '/catalog/<string:cat_name>/<int:item_id>/delete',
    methods=['GET', 'POST'])
def delete_item(cat_name, item_id):
    # Handle delete-item request
    item = session.query(Item).filter_by(id=item_id).one()
    creator = get_user_info(item.user_id)
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return redirect(url_for('redirect_login'))
    else:
        if request.method == 'POST':
            session.delete(item)
            session.commit()
            return redirect(url_for('main_page'))
        else:
            return render_template(
                'deleteitempage.html', item=item,
                cat_name=cat_name)


@app.route('/api/catalog.json')
def get_catalog_json():
    # Create json endpoint for the whole catalog
    categories = session.query(CatalogCategory).all()
    cat_json = []
    for category in categories:
        category_serialized = category.serialize
        items = session.query(Item).filter_by(cat_id=category.id)
        if items.first() is not None:
            category_serialized['Item'] = [item.serialize for item in items]
        cat_json.append(category_serialized)
    return jsonify(Category=cat_json)


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    # app.debug = True
    app.run(host='0.0.0.0', port=8000, threaded=True)
