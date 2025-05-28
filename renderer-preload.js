// This script runs in the context of the webview
// It can monitor the webview's content for potential security issues

// Set a trusted origin for postMessage
const trustedOrigin = window.location.origin;

// Function to detect potential phishing attempts in the page
function detectPhishingIndicators() {
  // Check for password fields on non-HTTPS pages
  const passwordFields = document.querySelectorAll('input[type="password"]');
  const isHttps = window.location.protocol === 'https:';
  
  if (passwordFields.length > 0 && !isHttps) {
    // Alert the main process that there's a password field on a non-secure page
    window.postMessage({
      type: 'security-warning',
      message: 'Password field detected on non-HTTPS page'
    }, trustedOrigin);
  }
  
  // Check for deceptive login forms
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const action = form.getAttribute('action');
    if (action && action !== '' && !action.startsWith('https:')) {
      const hasPasswordField = form.querySelector('input[type="password"]') !== null;
      if (hasPasswordField) {
        window.postMessage({
          type: 'security-warning',
          message: 'Login form submits to non-secure destination'
        }, trustedOrigin);
      }
    }
  });
}

// Intercept all link clicks to ensure phishing protection
function interceptLinkClicks() {
  // Use event delegation for efficiency
  document.addEventListener('click', (event) => {
    // Find if the click was on a link or within a link
    let target = event.target;
    while (target && target.tagName !== 'A') {
      target = target.parentElement;
      if (!target) return; // Not a link click
    }
    
    // Get the link's href
    const href = target.getAttribute('href');
    if (!href) return; // No href attribute
    
    // Skip internal page links
    if (href.startsWith('#')) return;
    
    // Block dangerous schemes: javascript:, data:, vbscript:
    const dangerousSchemes = ['javascript:', 'data:', 'vbscript:'];
    if (dangerousSchemes.some(scheme => href.toLowerCase().startsWith(scheme))) return;
    
    // Skip mailto: links
    if (href.startsWith('mailto:')) return;
    
    // Get absolute URL
    const url = new URL(href, window.location.href).href;
    
    // Prevent default navigation
    event.preventDefault();
    
    // Send message to parent to check and navigate
    window.postMessage({
      type: 'navigate',
      url: url
    }, trustedOrigin);
  });
}

// Monitor DOM changes to detect dynamic phishing content
const observer = new MutationObserver(() => {
  detectPhishingIndicators();
});

// Start observing the document
window.addEventListener('DOMContentLoaded', () => {
  detectPhishingIndicators();
  interceptLinkClicks();
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  // Notify about page load complete
  window.postMessage({
    type: 'page-ready',
    url: window.location.href,
    title: document.title,
    isSecure: window.location.protocol === 'https:'
  }, trustedOrigin);
});

// Inject CSS to highlight insecure elements
const style = document.createElement('style');
style.textContent = `
  form:not([action^="https://"]) input[type="password"] {
    border: 2px solid #ff0000 !important;
    background-color: rgba(255, 0, 0, 0.05) !important;
  }
`;
document.head.appendChild(style); 