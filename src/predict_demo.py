from joblib import load
import pandas as pd

model = load("models/ddos_model.joblib")

samples = pd.DataFrame([
    {
        "flow_duration": 52000,
        "packets_per_second": 22,
        "bytes_per_second": 1600,
        "syn_flag_count": 1,
        "udp_flag_count": 0
    },
    {
        "flow_duration": 4000,
        "packets_per_second": 620,
        "bytes_per_second": 32000,
        "syn_flag_count": 80,
        "udp_flag_count": 1
    }
], columns=[
    "flow_duration", "packets_per_second", "bytes_per_second",
    "syn_flag_count", "udp_flag_count"
])

predictions = model.predict(samples)
probabilities = model.predict_proba(samples).max(axis=1)

for i, prediction in enumerate(predictions):
    action = "ALLOW" if prediction == "BENIGN" else "RATE_LIMIT"
    print(f"Flow {i+1}: Prediction={prediction}, Confidence={probabilities[i]:.2f}, Action={action}")