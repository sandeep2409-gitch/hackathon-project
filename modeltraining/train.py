import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import sys

import os

_script_dir = os.path.dirname(os.path.abspath(__file__))
_backend = os.path.join(_script_dir, '..', 'backend')
sys.path.insert(0, os.path.abspath(_backend))
from features import extract_features

def train_with_multi_labels(csv_path):
    if not os.path.isabs(csv_path):
        csv_path = os.path.join(_script_dir, csv_path)
    df = pd.read_csv(csv_path) 
    map_dict = {
        'benign': 0,
        'phishing': 1,
        'defacement': 1,
        'malware': 1
    }
    df['label'] = df['type'].map(map_dict)
    
  
    print("Extracting features... this might take a few minutes for large files.")
    X = df['url'].apply(lambda x: extract_features(str(x))).tolist()
    y = df['label'].tolist()
    
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    
    
    model_path = os.path.join(_script_dir, '..', 'backend', 'phish_model.pkl')
    joblib.dump(model, model_path)
    print(f"Model trained! Accuracy: {model.score(X_test, y_test)*100:.2f}%")

if __name__ == "__main__":
    train_with_multi_labels('malicious_phish1.csv')