// Minimal helper to trigger MyInfo login redirect
// Usage in Blade: <script src="/vendor/myinfo/login.js"></script>
window.myinfoLogin = function (authorizeUrl) {
  if (!authorizeUrl) {
    console.error('Missing authorize URL');
    return;
  }
  window.location.assign(authorizeUrl);
};

