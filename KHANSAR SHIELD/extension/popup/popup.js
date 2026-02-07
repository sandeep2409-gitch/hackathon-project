chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const status = document.getElementById('res');
    fetch('http://127.0.0.1:8000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tabs[0].url })
    })
    .then(res => res.json())
    .then(data => {
        status.innerText = "Status: " + data.status.toUpperCase();
        status.style.color = data.status === "phishing" ? "red" : "green";
    });
});