import Layout from '../components/Layout';
import Link from 'next/link';

export default function Home() {
  return (
    <Layout title="Squawk DNS - Secure DNS-over-HTTPS System" page="home">
      {/* Hero Section */}
      <section className="hero bg-gradient-primary text-white py-5">
        <div className="container">
          <div className="row align-items-center min-vh-75">
            <div className="col-lg-6">
              <div className="hero-content">
                <div className="mb-3">
                  <span className="badge bg-light text-primary fs-6 px-3 py-2">
                    <i className="fas fa-shield-alt me-2"></i>Squawk DNS, a Penguin Cloud Solution
                  </span>
                </div>
                <h1 className="display-4 fw-bold mb-4">
                  Secure DNS-over-HTTPS
                  <span className="text-warning"> with Enterprise Authentication</span>
                </h1>
                <p className="lead mb-4">
                  Squawk DNS provides enterprise-grade DNS-over-HTTPS services with mTLS authentication, 
                  comprehensive security features, and high-performance infrastructure. Perfect for 
                  organizations requiring secure, authenticated DNS resolution.
                </p>
                
                <div className="hero-features mb-4">
                  <div className="row g-3">
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-shield-alt text-success me-2"></i>
                        <span>mTLS Authentication</span>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-rocket text-warning me-2"></i>
                        <span>High Performance</span>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-eye-slash text-info me-2"></i>
                        <span>DNS Privacy Protection</span>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-lock text-danger me-2"></i>
                        <span>Enterprise Security</span>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="hero-actions">
                  <Link href="/download" className="btn btn-light btn-lg me-3">
                    <i className="fas fa-download me-2"></i>
                    Download Free
                  </Link>
                  <Link href="/pricing" className="btn btn-outline-light btn-lg">
                    <i className="fas fa-dollar-sign me-2"></i>
                    View Pricing
                  </Link>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="hero-demo">
                <div className="card bg-dark text-light shadow-lg">
                  <div className="card-header bg-secondary">
                    <small><i className="fas fa-terminal me-2"></i>Squawk DNS Client</small>
                  </div>
                  <div className="card-body">
                    <pre className="mb-0"><code className="language-bash">{`# Quick Start with Docker
docker run -p 53:53/udp -p 53:53/tcp \\
  -e SQUAWK_SERVER_URL=https://dns.yourdomain.com:8443 \\
  -e SQUAWK_AUTH_TOKEN=your-secure-token \\
  penguincloud/squawk-dns-client:latest forward -v

# Or install natively  
wget https://github.com/penguincloud/squawk/releases/download/v1.1.1-client/squawk-dns-client_1.1.1_amd64.deb
sudo dpkg -i squawk-dns-client_1.1.1_amd64.deb
sudo systemctl enable --now squawk-dns-client`}</code></pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Overview */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Why Choose Squawk DNS?</h2>
              <p className="text-muted">Enterprise-grade DNS security with unmatched performance and features</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-primary text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-shield-virus fa-2x"></i>
                  </div>
                  <h5 className="card-title">Advanced Security</h5>
                  <p className="card-text text-muted">
                    mTLS authentication, DNS blackholing with Maravento integration, 
                    brute force protection, and comprehensive security logging.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-info text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-eye-slash fa-2x"></i>
                  </div>
                  <h5 className="card-title">DNS Privacy Protection</h5>
                  <p className="card-text text-muted">
                    Keep your services private - external endpoints accessible by IP 
                    without exposing them in public DNS records. Perfect for internal services.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-success text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-tachometer-alt fa-2x"></i>
                  </div>
                  <h5 className="card-title">High Performance</h5>
                  <p className="card-text text-muted">
                    HTTP/3 support, Redis caching, async processing, and Go client 
                    with ~10ms cold start and minimal memory usage.
                  </p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="row g-4 mt-4">
            <div className="col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-warning text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-users-cog fa-2x"></i>
                  </div>
                  <h5 className="card-title">Enterprise Ready</h5>
                  <p className="card-text text-muted">
                    SSO integration (SAML, LDAP, OAuth2), MFA support, 
                    web console, role-based access, and comprehensive auditing.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="col-md-6">
              <div className="card h-100 border-0 shadow-sm bg-light border-2">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-secondary text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-server fa-2x"></i>
                  </div>
                  <h5 className="card-title">Private Service Discovery</h5>
                  <p className="card-text text-muted">
                    <strong>Revolutionary approach to service privacy:</strong> Your external services 
                    remain accessible by IP address while staying completely invisible in public DNS. 
                    No DNS records = no attack surface for reconnaissance.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Statistics */}
      <section className="py-5 bg-primary text-white">
        <div className="container">
          <div className="row text-center">
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">10ms</h3>
                <p className="mb-0">Go Client Cold Start</p>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">1000+</h3>
                <p className="mb-0">Requests per Second</p>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">15MB</h3>
                <p className="mb-0">Memory Usage</p>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">2M+</h3>
                <p className="mb-0">Blocked Domains</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center">
              <h2 className="fw-bold mb-4">Ready to Secure Your DNS?</h2>
              <p className="lead text-muted mb-4">
                Get started with Squawk DNS today. Deploy in minutes with Docker or native packages.
              </p>
              
              <div className="cta-buttons">
                <Link href="/download" className="btn btn-primary btn-lg me-3">
                  <i className="fas fa-download me-2"></i>
                  Download Free Version
                </Link>
                <Link href="/pricing" className="btn btn-outline-primary btn-lg me-3">
                  <i className="fas fa-dollar-sign me-2"></i>
                  View Premium Plans
                </Link>
                <Link href="/contact" className="btn btn-outline-secondary btn-lg">
                  <i className="fas fa-envelope me-2"></i>
                  Contact Sales
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}