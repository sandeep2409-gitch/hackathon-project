document.getElementById('backBtn').addEventListener('click', () => {
    window.history.back();
});

document.getElementById('trustBtn').addEventListener('click', async () => {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get("url");

    if (blockedUrl) {
        try {
            await fetch('http://127.0.0.1:8000/whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: blockedUrl })
            });
            window.location.href = blockedUrl;
        } catch (e) {
            alert("Connection to Khansar Shield Core failed.");
        }
    }
});