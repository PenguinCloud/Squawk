import Layout from '../components/Layout';
import Link from 'next/link';

export default function Pricing() {
  return (
    <Layout title="Pricing - Squawk DNS" page="pricing">
      {/* Hero Section */}
      <section className="bg-gradient-primary text-white py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center">
              <div className="mb-3">
                <span className="badge bg-light text-primary fs-6 px-3 py-2">
                  <i className="fas fa-shield-alt me-2"></i>Squawk DNS, a Penguin Cloud Solution
                </span>
              </div>
              <h1 className="display-4 fw-bold mb-4">Simple, Transparent Pricing</h1>
              <p className="lead">Choose the right plan for your DNS security needs. Free for individual use, affordable for enterprise.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Cards */}
      <section className="py-5">
        <div className="container">
          <div className="row g-4 justify-content-center">
            {/* Community/Individual Plan */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-lg">
                <div className="card-body text-center p-5">
                  <div className="pricing-icon bg-success text-white rounded-circle mx-auto mb-4 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-user fa-2x"></i>
                  </div>
                  <h3 className="card-title mb-3">Community</h3>
                  <div className="price-display mb-4">
                    <h2 className="display-4 fw-bold text-success">Free</h2>
                    <p className="text-muted">Individual & Internal Use Only</p>
                  </div>
                  <ul className="list-unstyled mb-4">
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>All enterprise features included</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>mTLS authentication & security</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>DNS privacy protection</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>High performance HTTP/3</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Web console & monitoring</li>
                    <li className="mb-2 text-muted"><i className="fas fa-times text-muted me-2"></i>No commercial/external use</li>
                    <li className="mb-2 text-muted"><i className="fas fa-times text-muted me-2"></i>Community support only</li>
                  </ul>
                  <Link href="/download/" className="btn btn-success btn-lg w-100">
                    <i className="fas fa-download me-2"></i>Download Free
                  </Link>
                </div>
              </div>
            </div>

            {/* Enterprise Plan */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-primary border-3 shadow-lg position-relative">
                <div className="position-absolute top-0 start-50 translate-middle">
                  <span className="badge bg-primary px-3 py-2">Most Popular</span>
                </div>
                <div className="card-body text-center p-5">
                  <div className="pricing-icon bg-primary text-white rounded-circle mx-auto mb-4 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-building fa-2x"></i>
                  </div>
                  <h3 className="card-title mb-3">Enterprise</h3>
                  <div className="price-display mb-4">
                    <h2 className="display-4 fw-bold text-primary">$5</h2>
                    <p className="text-muted">per user/month</p>
                  </div>
                  <ul className="list-unstyled mb-4">
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>All Community features</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>mTLS authentication</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>SSO integration (SAML, LDAP, OAuth2)</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Multi-factor authentication</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Web management console</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Advanced monitoring & analytics</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Priority support</li>
                  </ul>
                  <a href="mailto:sales@penguincloud.io" className="btn btn-primary btn-lg w-100">
                    <i className="fas fa-envelope me-2"></i>Contact Sales
                  </a>
                </div>
              </div>
            </div>

            {/* Embedded/OEM Plan */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-lg">
                <div className="card-body text-center p-5">
                  <div className="pricing-icon bg-warning text-white rounded-circle mx-auto mb-4 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-microchip fa-2x"></i>
                  </div>
                  <h3 className="card-title mb-3">Embedded/OEM</h3>
                  <div className="price-display mb-4">
                    <h2 className="display-4 fw-bold text-warning">Custom</h2>
                    <p className="text-muted">Contact for Pricing</p>
                  </div>
                  <ul className="list-unstyled mb-4">
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>All Enterprise features</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>White-label licensing</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Custom branding</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>OEM distribution rights</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Custom feature development</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Dedicated support team</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>SLA guarantees</li>
                  </ul>
                  <a href="mailto:sales@penguincloud.io" className="btn btn-warning btn-lg w-100">
                    <i className="fas fa-handshake me-2"></i>Contact Sales
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Frequently Asked Questions</h2>
              <p className="text-muted">Common questions about Squawk DNS pricing and licensing</p>
            </div>
          </div>
          <div className="row justify-content-center">
            <div className="col-lg-8">
              <div className="accordion" id="pricingFAQ">
                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#faq1">
                      What qualifies as &quot;individual or internal use&quot; for the free Community plan?
                    </button>
                  </h2>
                  <div id="faq1" className="accordion-collapse collapse show" data-bs-parent="#pricingFAQ">
                    <div className="accordion-body">
                      The Community plan is free for personal use, educational purposes, and internal company use where you are not providing DNS services to external customers or charging for DNS-related services. Commercial service providers must use the Enterprise plan.
                    </div>
                  </div>
                </div>
                
                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq2">
                      How is &quot;per user&quot; calculated for Enterprise pricing?
                    </button>
                  </h2>
                  <div id="faq2" className="accordion-collapse collapse" data-bs-parent="#pricingFAQ">
                    <div className="accordion-body">
                      Enterprise pricing is based on the number of unique users who authenticate to your Squawk DNS system each month. This includes employees, contractors, and any other individuals with DNS access credentials. Device-based licensing is also available for high-device, low-user scenarios.
                    </div>
                  </div>
                </div>

                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq3">
                      What support is included with each plan?
                    </button>
                  </h2>
                  <div id="faq3" className="accordion-collapse collapse" data-bs-parent="#pricingFAQ">
                    <div className="accordion-body">
                      Community plan includes community forums and GitHub issues. Enterprise plan includes email support with 24-hour response time and access to our knowledge base. Embedded/OEM plans include dedicated support teams with SLA guarantees and phone support.
                    </div>
                  </div>
                </div>

                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq4">
                      Can I upgrade from Community to Enterprise later?
                    </button>
                  </h2>
                  <div id="faq4" className="accordion-collapse collapse" data-bs-parent="#pricingFAQ">
                    <div className="accordion-body">
                      Yes! Upgrading is seamless. Your existing configuration and data are preserved. Contact our sales team to discuss migration assistance and enterprise onboarding support.
                    </div>
                  </div>
                </div>

                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq5">
                      Do you offer volume discounts or annual billing?
                    </button>
                  </h2>
                  <div id="faq5" className="accordion-collapse collapse" data-bs-parent="#pricingFAQ">
                    <div className="accordion-body">
                      Yes! We offer significant discounts for annual billing and volume licensing for organizations with 100+ users. Contact our sales team at sales@penguincloud.io for custom pricing.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section className="py-5 bg-primary text-white">
        <div className="container">
          <div className="row text-center">
            <div className="col-lg-12">
              <h3 className="fw-bold mb-4">Ready to Get Started?</h3>
              <p className="lead mb-4">Choose your plan or contact our sales team for custom requirements.</p>
              <div className="d-flex gap-3 justify-content-center flex-wrap">
                <Link href="/download/" className="btn btn-light btn-lg">
                  <i className="fas fa-download me-2"></i>Try Free Community
                </Link>
                <a href="mailto:sales@penguincloud.io" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-envelope me-2"></i>Contact Sales Team
                </a>
                <Link href="/documentation/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-book me-2"></i>View Documentation
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}