chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
        fetch('http://127.0.0.1:8000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "phishing") {
                chrome.tabs.update(tabId, { url: chrome.runtime.getURL("blocked.html") });
            }
        }).catch(err => console.log("API Offline"));
    }
});