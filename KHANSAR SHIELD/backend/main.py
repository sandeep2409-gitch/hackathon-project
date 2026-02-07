from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import re
from urllib.parse import urlparse
import uvicorn

def extract_features(url):
    url = str(url).lower().strip()
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    
    features = [
        len(url),
        url.count('.'),
        url.count('-'),
        path.count('/'),
        1 if "@" in url else 0,
        1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname) else 0,
        1 if url.startswith("https") else 0,
        1 if any(word in url for word in ['login', 'verify', 'update', 'bank', 'secure']) else 0,
        1 if any(s in hostname for s in ["bit.ly", "t.co", "goo.gl", "tinyurl"]) else 0
    ]
    return [features]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
SAFE_SITES = ["google.com", "youtube.com", "github.com", "apple.com", "wikipedia.org"]
DANGER_PATTERNS = ["secure-login", "verify-account", "update-bank", "free-crypto"]


try:
    model = joblib.load("phish_model.pkl")
    print("AI Model Loaded")
except:
    model = None
    print("AI Model missing - using lists only")

class URLRequest(BaseModel):
    url: str



@app.get("/")
def home():
   
    return {"status": "Online", "message": "Khansar Shield Backend is Live"}

@app.post("/predict")
async def predict(data: URLRequest):
    url_clean = data.url.lower().strip()

  
    if any(domain in url_clean for domain in SAFE_SITES):
        return {"status": "safe", "reason": "Trusted Domain"}

    
    if any(pattern in url_clean for pattern in DANGER_PATTERNS):
        return {"status": "phishing", "reason": "Known Threat Pattern"}

   
    if model:
        prediction = model.predict(extract_features(data.url))
        return {
            "status": "phishing" if prediction[0] == 1 else "safe",
            "reason": "AI Prediction"
        }

    return {"status": "safe", "reason": "No immediate threats found"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)