from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_pymongo import PyMongo
from bson import ObjectId  # Import ObjectId from bson module
from datetime import datetime
from dotenv import load_dotenv
import pickle
import numpy as np
import sys
import os

load_dotenv()

filename = 'diabetes.pkl'
classifier = pickle.load(open(filename, 'rb'))


app = Flask(__name__)
CORS(app)
app.config['MONGO_URI'] = os.getenv('URL')
mongo = PyMongo(app)

class DiabetesModel:
    # Define your model fields here
    pass

# Convert ObjectId to string for JSON serialization
def convert_to_json(data):
    for entry in data:
        entry['_id'] = str(entry['_id'])
    return data

@app.route('/')
def get_data():
    try:
        data = list(mongo.db.diabetes.find())
        return jsonify(convert_to_json(data)), 200
    except Exception as e:
        return {"message": str(e)}, 400

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
        tracked['_id'] = str(inserted_id)  # Convert ObjectId to string

        return {"message": "Data added successfully", "data": tracked}, 200
    except Exception as e:
        return {"message": str(e)}, 400
    

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

            # Return the prediction as a JSON response
            return jsonify({"data": prediction_list}), 200

    except:
        ops = str(sys.exc_info())
        return f'<h1>Oops! {ops} occurred</h1>'


if __name__ == '__main__':
    app.run(debug=True, port=5000)
