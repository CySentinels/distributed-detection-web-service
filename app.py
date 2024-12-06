import asyncio

import joblib
import pandas as pd
from flask import Flask, jsonify, request
from sklearn.preprocessing import LabelEncoder

from extract_features import process_urls

app = Flask(__name__)


lock = asyncio.Lock()

# Load the trained model
model_path = "models/rf_model_phiusiil_v3.1.pkl"
best_rf_model = joblib.load(model_path)

# Load training feature template for alignment
required_features = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLD",
    "TLDLength",
    "NoOfSubDomain",
    "IsHTTPS",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "LetterRatioInURL",
    "DegitRatioInURL",
    "SpacialCharRatioInURL",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "URLCharProb",
    "TLDLegitimateProb",
]


# Create a function to prepare features for prediction
def prepare_features(input_features, required_features):
    full_features = {
        feature: input_features.get(feature, 0) for feature in required_features
    }
    return pd.DataFrame([full_features])


# Encode categorical features
label_encoder = LabelEncoder()


@app.route("/predict", methods=["GET"])
async def predict():
    """
    GET endpoint for model predictions.
    Expects a 'url' query parameter, extracts features using extract_features(),
    and returns predictions.
    """
    urls = []

    try:
        # Get URL from query parameters
        input_url = request.args.get("url")
        if not input_url:
            return jsonify({"error": "Missing 'url' query parameter."}), 400
        urls.append(input_url)

        # Extract features using the implemented function
        features_list = process_urls(urls) 
        # Align features with the trained model's feature set
        prepared_features = prepare_features(features_list[0], required_features)

        for col in ['TLD']:
            prepared_features[col] = label_encoder.fit_transform(prepared_features[col])

        if prepared_features.empty:
            return jsonify(
                {"error": "No features extracted from the provided URL."}
            ), 400

        # Perform prediction
        async with lock:  # Ensure thread-safe model access
            prediction = best_rf_model.predict(prepared_features)
            result = "Legitimate" if prediction[0] == 1 else "Phishing"

        return jsonify({"prediction": result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint to verify service is running.
    """
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    # Run the Flask app with asyncio support
    import os

    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    config = Config()
    config.bind = [f"0.0.0.0:{os.getenv('PORT', 5000)}"]
    asyncio.run(serve(app, config))
