import joblib
import pandas as pd
import numpy as np
from fastapi import FastAPI, Request, HTTPException
from sklearn.preprocessing import StandardScaler
import warnings

warnings.filterwarnings('ignore')

# Initialize FastAPI App
app = FastAPI()

# Load trained model and label encoders
try:
    model = joblib.load("cybersecurity_model.pkl")
    label_encoders = joblib.load("label_encoders.pkl")
except Exception as e:
    print(f"Error loading model: {str(e)}")
    raise

# Define expected features
FEATURES = ["Protocol", "Traffic Type", "Action Taken", "Severity Level", 
            "Network Segment", "User-Agent", "Source Port", "Destination Port", 
            "Packet Length", "Anomaly Scores"]

CATEGORICAL_FEATURES = ["Protocol", "Traffic Type", "Action Taken", "Severity Level", 
                        "Network Segment", "User-Agent"]
NUMERIC_FEATURES = ["Source Port", "Destination Port", "Packet Length", "Anomaly Scores"]

def preprocess_request(data: dict):
    """Preprocess a single request for prediction."""
    try:
        df = pd.DataFrame([data])

        # Ensure all expected columns exist
        for col in FEATURES:
            if col not in df.columns:
                df[col] = 0

        # Handle categorical features
        for col in CATEGORICAL_FEATURES:
            if col in df.columns:
                df[col] = df[col].astype(str)
                if col in label_encoders:
                    le = label_encoders[col]
                    try:
                        df[col] = le.transform(df[col])
                    except ValueError:
                        df[col] = df[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)


        # Handle numeric features
        scaler = StandardScaler()
        for col in NUMERIC_FEATURES:
            if col in df.columns:
                df[col] = scaler.fit_transform(df[[col]])

        # Ensure correct feature order
        df = df[FEATURES]
        return df

    except Exception as e:
        raise ValueError(f"Error in preprocessing: {str(e)}")


def deep_packet_inspection(request_data):
    """
    Performs Deep Packet Inspection (DPI) on blocked requests.
    Scans for anomalies, malware signatures, or suspicious payload data.
    """
    try:
        # 🚀 Example: Check for suspicious payload keywords
        suspicious_keywords = ["malware", "exploit", "trojan", "phishing", "attack"]
        
        # Convert request data to string for scanning
        raw_data = str(request_data).lower()
        
        detected_signatures = [keyword for keyword in suspicious_keywords if keyword in raw_data]

        if detected_signatures:
            return {
                "dpi_status": "Threat Detected",
                "malicious_content": detected_signatures
            }
        else:
            return {
                "dpi_status": "No Threat Detected"
            }
    
    except Exception as e:
        return {
            "dpi_status": "DPI Error",
            "error": str(e)
        }


@app.post("/predict/")
async def predict(request: Request):
    """Analyze incoming request & classify as malicious or safe."""
    try:
        data = await request.json()

        # Validate input data
        missing_features = [f for f in FEATURES if f not in data]
        if missing_features:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required features: {missing_features}"
            )

        # Preprocess the request
        processed_data = preprocess_request(data)

        # Make prediction
        prediction = model.predict(processed_data)[0]
        probability = model.predict_proba(processed_data)[0]

        # Get feature importance scores
        importance_scores = dict(zip(FEATURES, abs(model.coef_[0])))
        top_features = dict(sorted(
            importance_scores.items(), 
            key=lambda x: abs(x[1]), 
            reverse=True
        )[:3])

        response = {
            "status": "Blocked" if prediction == 1 else "Allowed",
            "confidence": float(max(probability)),
            "risk_score": float(probability[1]),  # Probability of being malicious
            "key_indicators": top_features,
            "prediction": int(prediction),
            "timestamp": pd.Timestamp.now().isoformat()
        }

        # If blocked, send request to Deep Packet Inspection (DPI)
        if prediction == 1:
            dpi_result = deep_packet_inspection(data)
            response["dpi_result"] = dpi_result

        return response

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction error: {str(e)}"
        )


@app.get("/health/")
async def health_check():
    """API health check endpoint."""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "encoders_loaded": label_encoders is not None
    }
