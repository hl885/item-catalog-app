# Catalog Website
The website provides a list of categories and items. The Google authentication is used to authenticate and authorize a user, and let the user create, modify and delete the user's own items. [Demo site](http://itemcatapp.herokuapp.com/)

## Requirements
- [Python 3](https://www.python.org/downloads/)
- [SQLAlchemy](https://www.sqlalchemy.org/download.html)
- [oauth2client](https://oauth2client.readthedocs.io/en/latest/)
- [Flask](http://flask.pocoo.org/)
- [httplib2](http://httplib2.readthedocs.io/en/latest/)
- [requests](http://docs.python-requests.org/en/master/)

## Usage
To run the program, do the following steps:
1. Run the server in the command line with:
    ```
    ./views.py
    ```
2. In the browser, visit the following link to setup the database:
    ```
    http://localhost:8000/init_catalog
    ```
3. Visit the website with:
    ```
    http://localhost:8000/
    ```
