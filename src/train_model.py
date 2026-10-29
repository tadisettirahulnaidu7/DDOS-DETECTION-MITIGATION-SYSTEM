import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from joblib import dump

np.random.seed(42)

# Safe synthetic traffic-flow data for demo only
normal = pd.DataFrame({
    "flow_duration": np.random.normal(50000, 8000, 1000),
    "packets_per_second": np.random.normal(20, 5, 1000),
    "bytes_per_second": np.random.normal(1500, 300, 1000),
    "syn_flag_count": np.random.randint(0, 3, 1000),
    "udp_flag_count": np.random.randint(0, 2, 1000),
    "label": "BENIGN"
})

attack = pd.DataFrame({
    "flow_duration": np.random.normal(5000, 1000, 1000),
    "packets_per_second": np.random.normal(500, 100, 1000),
    "bytes_per_second": np.random.normal(30000, 5000, 1000),
    "syn_flag_count": np.random.randint(30, 100, 1000),
    "udp_flag_count": np.random.randint(0, 2, 1000),
    "label": "DDOS"
})

data = pd.concat([normal, attack], ignore_index=True)
data.to_csv("data/traffic_data.csv", index=False)

X = data.drop("label", axis=1)
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print("MODEL ACCURACY:", round(accuracy * 100, 2), "%")
print("\nCLASSIFICATION REPORT:\n", classification_report(y_test, predictions))
print("CONFUSION MATRIX:\n", confusion_matrix(y_test, predictions))

dump(model, "models/ddos_model.joblib")
print("\nModel saved successfully: models/ddos_model.joblib")