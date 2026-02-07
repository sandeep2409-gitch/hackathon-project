import os
import joblib
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

from features import extract_features

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_MODEL_PATH = os.path.join(_BACKEND_DIR, "phish_model.pkl")
_DATA_DIR = os.path.join(_BACKEND_DIR, "data")

def _load_lines(filename: str) -> list[str]:
    path = os.path.join(_DATA_DIR, filename)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]

app = FastAPI()

# Enable CORS for Chrome Extension and Web Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration: Trust and Threat Lists
SAFE_SITES = [
    "google.com",
    "youtube.com",
    "github.com",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "netflix.com",
    "wikipedia.org",
    "reddit.com",
    "paypal.com",
    "spotify.com",
    "adobe.com",
    "cloudflare.com",
    "mozilla.org",
    "stackoverflow.com",
    "medium.com",
    "dropbox.com",
    "zoom.us",
    "slack.com",
    "discord.com",
    "twitch.tv",
    "yahoo.com",
    "bing.com",
    "outlook.com",
    "office.com",
    "live.com",
    "icloud.com",
    "notion.so",
    "figma.com",
    "npmjs.com",
    "pypi.org",
    # 100 more trusted sites
    "ebay.com",
    "aliexpress.com",
    "walmart.com",
    "target.com",
    "bestbuy.com",
    "costco.com",
    "etsy.com",
    "shopify.com",
    "craigslist.org",
    "booking.com",
    "airbnb.com",
    "expedia.com",
    "tripadvisor.com",
    "kayak.com",
    "hotels.com",
    "uber.com",
    "lyft.com",
    "doordash.com",
    "grubhub.com",
    "ubereats.com",
    "instacart.com",
    "fedex.com",
    "ups.com",
    "usps.com",
    "dhl.com",
    "canva.com",
    "trello.com",
    "asana.com",
    "atlassian.com",
    "jira.com",
    "bitbucket.org",
    "gitlab.com",
    "heroku.com",
    "vercel.com",
    "netlify.com",
    "digitalocean.com",
    "aws.amazon.com",
    "azure.microsoft.com",
    "stripe.com",
    "squareup.com",
    "venmo.com",
    "zellepay.com",
    "coinbase.com",
    "binance.com",
    "kraken.com",
    "roblox.com",
    "minecraft.net",
    "epicgames.com",
    "steampowered.com",
    "ea.com",
    "nvidia.com",
    "amd.com",
    "intel.com",
    "samsung.com",
    "lg.com",
    "sony.com",
    "hp.com",
    "dell.com",
    "lenovo.com",
    "asus.com",
    "acer.com",
    "logitech.com",
    "razer.com",
    "coursera.org",
    "udemy.com",
    "edx.org",
    "khanacademy.org",
    "duolingo.com",
    "skillshare.com",
    "pluralsight.com",
    "indeed.com",
    "glassdoor.com",
    "monster.com",
    "ziprecruiter.com",
    "cnn.com",
    "bbc.com",
    "nytimes.com",
    "reuters.com",
    "apnews.com",
    "npr.org",
    "wsj.com",
    "theguardian.com",
    "forbes.com",
    "bloomberg.com",
    "techcrunch.com",
    "theverge.com",
    "arstechnica.com",
    "wired.com",
    "engadget.com",
    "cnet.com",
    "mashable.com",
    "vimeo.com",
    "dailymotion.com",
    "soundcloud.com",
    "bandcamp.com",
    "deezer.com",
    "tidal.com",
    "pandora.com",
    "audible.com",
    "goodreads.com",
    "imdb.com",
    "rottentomatoes.com",
    "metacritic.com",
    "fandom.com",
    "wikimedia.org",
    "archive.org",
    "brave.com",
    "duckduckgo.com",
    "startpage.com",
    "protonmail.com",
    "tutanota.com",
    "mailchimp.com",
    "sendgrid.com",
    "hubspot.com",
    "salesforce.com",
    "zendesk.com",
    "intercom.com",
    "calendly.com",
    "docusign.com",
    "grammarly.com",
    "lastpass.com",
    "1password.com",
    "bitwarden.com",
    "expressvpn.com",
    "nordvpn.com",
    "substack.com",
    "patreon.com",
    "giphy.com",
]
# Load 999 extra safe sites from data file
SAFE_SITES.extend(_load_lines("safe_sites_extra.txt"))

# Unsafe: known phishing/malware keywords in URL and blocklisted domains
DANGER_KEYWORDS = ["secure-login-verify", "update-bank-info", "free-crypto"]
DANGER_KEYWORDS.extend(_load_lines("unsafe_keywords.txt"))
UNSAFE_SITES = _load_lines("unsafe_sites.txt")

# Load AI Model
try:
    model = joblib.load(_MODEL_PATH)
    print("✅ Khansar AI Model Active")
except Exception:
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

    # 3. Blocklisted unsafe domains
    if any(bad in domain for bad in UNSAFE_SITES):
        return {"status": "phishing", "reason": "Known threat domain"}

    # 4. Phishing keywords in URL
    if any(kw in url_clean for kw in DANGER_KEYWORDS):
        return {"status": "phishing", "reason": "Suspicious URL pattern"}

    # 5. AI Analysis (Only if NOT whitelisted)
    if model:
        features = [extract_features(url_clean)]
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