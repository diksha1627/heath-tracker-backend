from datetime import datetime, timedelta
import os
import pathlib
import pickle
import sys

from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, request, jsonify, session, abort, redirect, render_template
from flask_cors import CORS
from flask_pymongo import PyMongo
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from cachecontrol import CacheControl
import google.auth.transport.requests
import requests
import numpy as np

load_dotenv()

app = Flask(__name__)
CORS(app)
app.config['MONGO_URI'] = os.getenv('URL')
app.secret_key = "diksha"
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
mongo = PyMongo(app)

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "./client_secret.json")

def create_google_auth_flow():
    return Flow.from_client_secrets_file(
        client_secrets_file=client_secrets_file,
        scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri="http://127.0.0.1:5000/callback"
    )

flow = create_google_auth_flow()

filename = 'diabetes.pkl'
classifier = pickle.load(open(filename, 'rb'))

def convert_to_json(data):
    for entry in data:
        entry['_id'] = str(entry['_id'])
    return data

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(404)
        else:
            return function()
    return wrapper

@app.errorhandler(Exception)
def handle_error(e):
    return render_template('error.html', error_message=str(e))

@app.route('/')
def get_data():
    try:
        data = list(mongo.db.diabetes.find())
        return jsonify(convert_to_json(data)), 200
    except Exception as e:
        return handle_error(e)
    
    
# @app.route('/diabetes', methods=['GET'])
# def get_diabetes_records():
#     try:
#         data = list(mongo.db.diabetes.find())
#         return jsonify(convert_to_json(data)), 200
#     except Exception as e:
#         return handle_error(e)    

@app.route('/signin')
def signin():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=1)
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)

        received_state = request.args["state"]
        if "state" not in session or session["state"] not in received_state:
            return render_template('error.html', error_message='Invalid state parameter')

        credentials = flow.credentials
        request_session = requests.Session()
        cached_session = CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials.id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )

        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")

        # ⚡ NEW: send React a token
        token = credentials.id_token

        return redirect(f"http://localhost:3000/auth/success?token={token}")
    except Exception as e:
        return handle_error(e)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/signin")

@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"

@app.route('/diabetes', methods=['POST'])
def add_diabetes_data():
    try:
        data = request.get_json()
        level = data.get('bloodSugarLevel')
        date = data.get('date')
        notes = data.get('notes')

        tracked = {
            'bloodSugarLevel': level,
            'date': date,
            'notes': notes
        }

        result = mongo.db.diabetes.insert_one(tracked)
        inserted_id = result.inserted_id
        tracked['_id'] = str(inserted_id)

        return {"message": "Data added successfully", "data": tracked}, 200
    except Exception as e:
        return handle_error(e)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        if request.method == 'POST':
            data = request.get_json()
            preg = data['pregnancies']
            glucose = data['glucose']
            bp = data['bloodpressure']
            st = data['skinthickness']
            insulin = data['insulin']
            bmi = data['bmi']
            dpf = data['dpf']
            age = data['age']
            data = np.array([[preg, glucose, bp, st, insulin, bmi, dpf, age]])
            my_prediction = classifier.predict(data)

            prediction_list = my_prediction.tolist()

            return jsonify({"data": prediction_list}), 200
    except Exception as e:
        return handle_error(e)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
