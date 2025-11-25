from datetime import datetime, timedelta
import os
import pathlib
import pickle
import sys
import json  # <-- added

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


FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN")
CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": [FRONTEND_ORIGIN]}},  # keep your exact frontend origin
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.secret_key = "diksha"
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
REDIRECT_URI = os.getenv("REDIRECT_URI")
mongo = PyMongo(app)

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

# allow either env JSON or local file (no logic change elsewhere)
CLIENT_SECRET_JSON = os.getenv("CLIENT_SECRET_JSON")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "./client_secret.json")

def create_google_auth_flow():
    # prefer env-provided JSON; fallback to file
    if CLIENT_SECRET_JSON:
        cfg = json.loads(CLIENT_SECRET_JSON)
        if "web" not in cfg:
            cfg = {"web": cfg}
        return Flow.from_client_config(
            client_config=cfg,
            scopes=[
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
            ],
            redirect_uri=REDIRECT_URI
        )
    return Flow.from_client_secrets_file(
        client_secrets_file=client_secrets_file,
        scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri=REDIRECT_URI
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

@app.route('/signin')
def signin():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route("/api/user", methods=["GET"])
def get_logged_user():
    if "google_id" not in session:
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "user": {
            "google_id": session.get("google_id"),
            "email": session.get("email"),
            "name": session.get("name"),
            "picture": session.get("picture")
        }
    }), 200

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
        session["email"] = id_info.get("email")
        session["picture"] = id_info.get("picture")

        now_utc = datetime.utcnow()
        mongo.db.users.update_one(
               {"google_id": id_info.get("sub")},
    {
        # update on every login
        "$set": {
            "name": id_info.get("name"),
            "email": id_info.get("email"),
            "picture": id_info.get("picture"),
            "email_verified": id_info.get("email_verified"),  # optional, useful
            "updated_at": now_utc,
        },
        # only when creating the user
        "$setOnInsert": {
            "google_id": id_info.get("sub"),
            "created_at": now_utc,
        },
    },
    upsert=True,
        )

        token = credentials.id_token

        return redirect(f"{FRONTEND_ORIGIN}/auth/success?token={token}")
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
        if "google_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        
        data = request.get_json()
        level = data.get('bloodSugarLevel')
        date = data.get('date')
        notes = data.get('notes')

        tracked = {
            'user_google_id': session['google_id'],
            'email': session.get('email'),
            'name': session.get('name'),
            'bloodSugarLevel': level,
            'date': date,
            'notes': notes,
            'created_at': datetime.utcnow()
        }

        result = mongo.db.diabetes.insert_one(tracked)
        tracked['_id'] = str(result.inserted_id)

        return {"message": "Data added successfully", "data": tracked}, 200
    except Exception as e:
        return handle_error(e)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        if "google_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401

        d = request.get_json(force=True) or {}

        # parse safely (raise 400 for bad input)
        def _req(name, cast=float):
            if name not in d:
                raise ValueError(f"Missing field: {name}")
            try:
                return cast(d[name])
            except Exception:
                raise ValueError(f"Invalid number for: {name}")

        preg = _req('pregnancies', int)
        glucose = _req('glucose', float)
        bp = _req('bloodpressure', float)
        st = _req('skinthickness', float)
        insulin = _req('insulin', float)
        bmi = _req('bmi', float)
        dpf = _req('dpf', float)
        age = _req('age', int)

        X = np.array([[preg, glucose, bp, st, insulin, bmi, dpf, age]])
        y = classifier.predict(X)
        result = int(y[0])

        # persist per-user
        doc = {
            "user_google_id": session["google_id"],
            "email": session.get("email"),
            "name": session.get("name"),
            "inputs": {
                "pregnancies": preg,
                "glucose": glucose,
                "bloodpressure": bp,
                "skinthickness": st,
                "insulin": insulin,
                "bmi": bmi,
                "dpf": dpf,
                "age": age,
            },
            "result": result,
            "created_at": datetime.utcnow(),
        }
        ins = mongo.db.predictions.insert_one(doc)
        saved_id = str(ins.inserted_id)

        return jsonify({"data": [result], "saved": {"_id": saved_id}}), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return handle_error(e)

@app.route('/predict/history', methods=['GET'])
def predict_history():
    try:
        if "google_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        cur = mongo.db.predictions.find({"user_google_id": session["google_id"]}).sort("created_at", -1)
        items = []
        for d in cur:
            d["_id"] = str(d["_id"])
            items.append(d)
        return jsonify({"items": items}), 200
    except Exception as e:
        return handle_error(e)


@app.route('/diabetes', methods=['GET'])
def get_diabetes_data():
    try:
        if "google_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        cursor = mongo.db.diabetes.find({"user_google_id": session["google_id"]}).sort("created_at", -1)
        items = []
        for d in cursor:
            d["_id"] = str(d["_id"])
            items.append(d)
        return jsonify(items), 200
    except Exception as e:
        return handle_error(e)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
