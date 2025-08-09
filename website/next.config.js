/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable static export for Cloudflare Pages
  output: 'export',
  
  // Disable image optimization for static export
  images: {
    unoptimized: true
  },
  
  // Configure trailing slash
  trailingSlash: true,
  
  // Configure base path (if needed for subdirectory deployment)
  // basePath: '',
  
  // Configure asset prefix for CDN
  // assetPrefix: '',
  
  // Environment variables
  env: {
    CUSTOM_VERSION: process.env.npm_package_version || '1.1.1',
  },
  
  // Note: redirects and headers don't work with static export
  // These will be handled by wrangler.toml instead
}

module.exports = nextConfig