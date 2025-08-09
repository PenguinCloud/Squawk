// Simple Cloudflare Worker for Express app
const app = require('./server.js');

export default {
  async fetch(request, env, ctx) {
    // For now, just return a simple response
    // This confirms the worker is running
    const url = new URL(request.url);
    
    if (url.pathname === '/') {
      return new Response(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Squawk DNS - Secure DNS-over-HTTPS System</title>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
          <nav class="navbar navbar-dark bg-primary">
            <div class="container">
              <span class="navbar-brand">🛡️ Squawk DNS, a Penguin Cloud Solution</span>
            </div>
          </nav>
          <div class="container mt-5">
            <div class="row">
              <div class="col-md-8 mx-auto text-center">
                <h1 class="display-4">Secure DNS-over-HTTPS</h1>
                <p class="lead">Enterprise-grade DNS security with mTLS authentication and comprehensive features.</p>
                <a href="https://github.com/penguincloud/squawk" class="btn btn-primary btn-lg">View on GitHub</a>
              </div>
            </div>
          </div>
        </body>
        </html>
      `, {
        headers: { 'Content-Type': 'text/html' }
      });
    }
    
    return new Response('404 Not Found', { status: 404 });
  }
};