import re
import joblib
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Enable CORS for Chrome Extension and Web Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration: Trust and Threat Lists
SAFE_SITES = ["google.com", "youtube.com", "github.com", "apple.com"]
DANGER_KEYWORDS = ["secure-login-verify", "update-bank-info", "free-crypto"]

# Feature Extraction for the AI Model
def extract_features(url):
    url = str(url).lower().strip()
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    features = [
        len(url), url.count('.'), url.count('-'), path.count('/'),
        1 if "@" in url else 0,
        1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname) else 0,
        1 if url.startswith("https") else 0,
        1 if any(word in url for word in ['login', 'verify', 'bank', 'secure']) else 0,
        1 if any(s in hostname for s in ["bit.ly", "t.co", "goo.gl"]) else 0
    ]
    return [features]

# Load AI Model
try:
    model = joblib.load("phish_model.pkl")
    print("✅ Khansar AI Model Active")
except:
    model = None
    print("⚠️ Model missing - using list-only mode")

class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"status": "Online", "system": "Khansar Shield Core"}

# In your backend/main.py

@app.post("/predict")
async def predict(data: URLRequest):
    url_clean = data.url.lower().strip()
    
    # Extract the base domain (e.g., google.com)
    parsed_url = urlparse(url_clean)
    domain = parsed_url.netloc if parsed_url.netloc else url_clean.split('/')[0]
    
    # 1. THE ULTIMATE OVERRIDE: Google & System Sites
    # We check if 'google.com' is part of the domain string
    if any(trusted in domain for trusted in ["google.com", "gstatic.com", "googleusercontent.com"]):
        return {"status": "safe", "reason": "System Whitelist Override"}

    # 2. Manual SAFE_SITES check
    if any(site in domain for site in SAFE_SITES):
        return {"status": "safe", "reason": "Verified Trusted Domain"}

    # 3. AI Analysis (Only if NOT whitelisted)
    if model:
        features = extract_features(url_clean)
        prediction = model.predict(features)
        
        # If AI is wrong about a famous site, this is where we catch it
        if prediction[0] == 1:
            return {"status": "phishing", "reason": "AI Neural Verdict"}
            
    return {"status": "safe", "reason": "No immediate threats found"}

@app.post("/whitelist")
async def add_to_whitelist(data: URLRequest):
    domain = urlparse(data.url).netloc
    if domain and domain not in SAFE_SITES:
        SAFE_SITES.append(domain)
        return {"status": "success", "message": f"Trusting {domain}"}
    return {"status": "exists"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)