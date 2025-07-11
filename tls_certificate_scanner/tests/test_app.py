
import pytest
from playwright.sync_api import Page, expect
import time
import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tls_certificate_scanner.app import Domain, Base, engine as app_engine

# Set up test database
test_engine = create_engine('sqlite:///test_certificates.db')
TestSession = sessionmaker(bind=test_engine)
test_session = TestSession()
Base.metadata.create_all(test_engine)

@pytest.fixture(scope="module")
def page():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        yield page
        context.close()
        browser.close()

@pytest.fixture(autouse=True)
def setup_database():
    # Clean up test database before each test
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)

    # Add test domains
    test_domains = ['google.com', 'yahoo.com']
    for domain in test_domains:
        if not test_session.query(Domain).filter_by(url=domain).first():
            new_domain = Domain(url=domain)
            test_session.add(new_domain)
            test_session.commit()

def test_app_runs(page):
    """Test that the app starts and main page loads"""
    page.goto("http://localhost:53468")
    expect(page).to_have_title("TLS Certificate Scanner")
    expect(page.locator("h1")).to_contain_text("TLS Certificate Scanner")

def test_add_domain(page):
    """Test adding a new domain"""
    page.goto("http://localhost:53468")

    # Add a new domain
    page.fill("input[name='url']", "test.com")
    page.click("text=Add Domain")

    # Check that the domain appears in the list
    expect(page.locator("text=test.com")).to_be_visible()

def test_remove_domain(page):
    """Test removing a domain"""
    page.goto("http://localhost:53468")

    # Find a domain to remove (should be google.com or yahoo.com from setup)
    domain_to_remove = page.locator("text=google.com")
    if not domain_to_remove.is_visible():
        domain_to_remove = page.locator("text=yahoo.com")

    # Remove the domain
    domain_to_remove.locator("xpath=..").locator(".actions .remove-btn").click()
    page.on("dialog", lambda dialog: dialog.accept())

    # Check that the domain is no longer visible
    expect(domain_to_remove).not_to_be_visible()

def test_scan_domain(page):
    """Test scanning a domain"""
    page.goto("http://localhost:53468")

    # Find a domain to scan (should be google.com or yahoo.com from setup)
    domain_to_scan = page.locator("text=google.com")
    if not domain_to_scan.is_visible():
        domain_to_scan = page.locator("text=yahoo.com")

    # Scan the domain
    domain_to_scan.locator("xpath=..").locator(".actions .scan-btn").click()

    # Check that the scan completed (we can check for the last scan timestamp)
    expect(domain_to_scan.locator("xpath=.. .details")).to_contain_text("Last scan:")

def test_certificate_details(page):
    """Test viewing certificate details"""
    page.goto("http://localhost:53468")

    # Find a domain to view details for (should be google.com or yahoo.com from setup)
    domain_link = page.locator("text=google.com")
    if not domain_link.is_visible():
        domain_link = page.locator("text=yahoo.com")

    # Go to certificate details
    domain_link.locator("xpath=..").locator(".actions .details-btn").click()

    # Check that we're on the details page
    expect(page).to_have_url("/certificate/")

    # Check that certificate details are displayed
    expect(page.locator("h1")).to_contain_text("Certificate Details")
    expect(page.locator("label=Subject")).to_be_visible()
    expect(page.locator("label=Issuer")).to_be_visible()
    expect(page.locator("label=Valid Until")).to_be_visible()

def test_scan_all(page):
    """Test scanning all domains"""
    page.goto("http://localhost:53468")

    # Scan all domains
    page.click("text=Scan All Domains")

    # Check that all domains have been scanned (we can check for the last scan timestamp)
    domains = page.locator(".domain-item")
    for domain in domains.element_handles():
        expect(domain.locator(".details")).to_contain_text("Last scan:")

if __name__ == "__main__":
    # Run the app in the background for testing
    import threading
    from tls_certificate_scanner.app import app

    def run_app():
        app.run(host='0.0.0.0', port=53468, debug=False)

    # Start the Flask app in a separate thread
    app_thread = threading.Thread(target=run_app)
    app_thread.daemon = True
    app_thread.start()

    # Wait for the app to start
    time.sleep(2)

    # Run the tests
    pytest.main([__file__, "-v"])

    # Clean up
    Base.metadata.drop_all(test_engine)

