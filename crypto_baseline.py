import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import numpy as np

# 1. Create Mock Network Data (Packet Size, Network Speed, Connection Duration)
# 0 = Normal Traffic, 1 = Hacker Attack
mock_data = {
    'packet_size': [250, 240, 260, 900, 255, 950, 248, 910],
    'speed_mbps':  [100, 105, 98,  20,  102, 15,  99,  22],
    'duration_s':  [5,   6,   5,   45,  5,   50,  6,   42],
    'is_attack':   [0,   0,   0,   1,   0,   1,   0,   1]
}

df = pd.DataFrame(mock_data)

# 2. Train the Classical AI Model
X = df[['packet_size', 'speed_mbps', 'duration_s']] # Features
y = df['is_attack'] # Labels

# Train a basic Logistic Regression model
classical_ai = LogisticRegression()
classical_ai.fit(X, y)

print("Classical AI Model Trained Successfully!")

# 3. Test the AI on a new, unseen network connection
new_connection = pd.DataFrame({'packet_size': [255], 'speed_mbps': [100], 'duration_s': [5]})
prediction = classical_ai.predict(new_connection)[0]

if prediction == 0:
    print("AI Analysis: Traffic looks NORMAL.")
else:
    print("AI Analysis: WARNING! Traffic looks SUSPICIOUS.")