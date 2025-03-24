import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

def preprocess_data(df, training=True):
    """Preprocess the dataset: clean, encode categorical features, normalize numeric features."""

    # ✅ Convert "Attack Type" to numeric to avoid string comparison errors
    if "Attack Type" in df.columns:
        df["Attack Type"] = pd.to_numeric(df["Attack Type"], errors="coerce").fillna(0).astype(int)

    # ✅ Define Expected Columns
    expected_columns = ["Protocol", "Traffic Type", "Action Taken", "Severity Level", 
                        "Network Segment", "User-Agent", "Source Port", "Destination Port", 
                        "Packet Length", "Anomaly Scores"]

    # ✅ Fill missing columns with default values
    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0  

    # ✅ Convert categorical features to numeric
    categorical_columns = ["Protocol", "Traffic Type", "Action Taken", "Severity Level", 
                           "Network Segment", "User-Agent"]
    
    label_encoders = {}
    for col in categorical_columns:
        if col in df.columns:
            df[col] = df[col].astype(str)
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            label_encoders[col] = le

    # ✅ Normalize numeric features
    numeric_columns = ["Source Port", "Destination Port", "Packet Length", "Anomaly Scores"]
    scaler = StandardScaler()
    df[numeric_columns] = scaler.fit_transform(df[numeric_columns])

    # ✅ If training, return both features & target
    if training and "Attack Type" in df.columns:
        df["Is_Malicious"] = df["Attack Type"].apply(lambda x: 1 if x > 0 else 0)
        X = df.drop(columns=["Attack Type", "Is_Malicious"], errors='ignore')
        y = df["Is_Malicious"]
        return X, y, label_encoders

    return df, label_encoders  # Return only X for inference
