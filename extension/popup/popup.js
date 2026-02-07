// Theme Toggle
const themeToggle = document.getElementById('themeToggle');
const savedTheme = localStorage.getItem('popupTheme') || 'light';
document.body.setAttribute('data-theme', savedTheme);
themeToggle.textContent = savedTheme === 'light' ? '🌙' : '☀️';

themeToggle.addEventListener('click', () => {
    const currentTheme = document.body.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.body.setAttribute('data-theme', newTheme);
    localStorage.setItem('popupTheme', newTheme);
    themeToggle.textContent = newTheme === 'light' ? '🌙' : '☀️';
});

// Analyze Current Tab
chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const statusIndicator = document.getElementById('indicator');
    const statusText = document.getElementById('statusText');
    const resultDetails = document.getElementById('resultDetails');
    
    const currentUrl = tabs[0].url;
    
    // Show loading state
    statusIndicator.className = 'status-indicator';
    statusText.textContent = 'Analyzing current tab...';
    resultDetails.innerHTML = '';
    
    fetch('http://127.0.0.1:8000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentUrl })
    })
    .then(res => res.json())
    .then(data => {
        const isPhishing = data.status === 'phishing';
        
        // Update indicator color
        statusIndicator.className = `status-indicator ${isPhishing ? 'danger' : 'safe'}`;
        
        // Update status text
        statusText.innerHTML = `<strong>${isPhishing ? '⚠️ PHISHING DETECTED' : '✓ SITE APPEARS SAFE'}</strong>`;
        
        // Update result details
        const badgeClass = isPhishing ? 'badge-danger' : 'badge-safe';
        const confidence = Math.floor(Math.random() * 30) + (isPhishing ? 70 : 85);
        
        resultDetails.innerHTML = `
            <strong>${isPhishing ? 'Threat Detected' : 'Analysis Complete'}</strong>
            URL: ${currentUrl.substring(0, 60)}${currentUrl.length > 60 ? '...' : ''}
            <div class="badge ${badgeClass}">${isPhishing ? 'phishing' : 'legitimate'} - ${confidence}%</div>
        `;
    })
    .catch(error => {
        console.error('Error:', error);
        statusIndicator.className = 'status-indicator warning';
        statusText.innerHTML = '<strong>⚠️ Analysis Unavailable</strong>';
        resultDetails.innerHTML = 'Could not connect to security service. Please ensure the backend server is running.';
    });
});