chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
        
        if (tab.url.includes("blocked.html")) return;

        fetch('http://127.0.0.1:8000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => { // Fixed: Ensure 'data' is defined here
            if (data.status === "phishing") {
                const blockedPageUrl = chrome.runtime.getURL("blocked.html") + 
                                      "?url=" + encodeURIComponent(tab.url);
                chrome.tabs.update(tabId, { url: blockedPageUrl });
            }
        })
        .catch(err => console.log("Shield Backend Offline"));
    }
});