
from flask import Flask, render_template, request, redirect, url_for, jsonify
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import ssl
import socket
import idna
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certificates.db'
app.config['SECRET_KEY'] = 'your-secret-key'

# Database setup
Base = declarative_base()
engine = create_engine('sqlite:///certificates.db')
Session = sessionmaker(bind=engine)
session = Session()

class Domain(Base):
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True)
    url = Column(String(255), unique=True, nullable=False)
    last_scan = Column(DateTime)
    expires_at = Column(DateTime)
    certificate_data = Column(Text)

Base.metadata.create_all(engine)

def get_certificate_info(domain):
    """Get certificate information for a domain"""
    try:
        # Handle IDN (Internationalized Domain Names)
        encoded_domain = idna.encode(domain).decode('ascii')

        context = ssl.create_default_context()
        with socket.create_connection((encoded_domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=encoded_domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert)

                # Parse certificate information
                subject = x509_cert.subject
                issuer = x509_cert.issuer
                serial_number = x509_cert.serial_number
                not_before = x509_cert.not_valid_before
                not_after = x509_cert.not_valid_after
                signature_hash_algorithm = x509_cert.signature_hash_algorithm

                # Get SANs (Subject Alternative Names)
                try:
                    san_extension = x509_cert.extensions.get_extension(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = san_extension.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    sans = []

                # Get CRL distribution points
                crl_dp = []
                try:
                    crl_extension = x509_cert.extensions.get_extension(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
                    for dp in crl_extension.value:
                        if isinstance(dp, x509.UniformResourceIdentifier):
                            crl_dp.append(dp.value)
                except x509.ExtensionNotFound:
                    pass

                return {
                    'domain': domain,
                    'subject': str(subject),
                    'issuer': str(issuer),
                    'serial_number': serial_number,
                    'not_before': not_before,
                    'not_after': not_after,
                    'signature_hash_algorithm': str(signature_hash_algorithm),
                    'sans': list(sans),
                    'crl_dp': crl_dp,
                    'valid': True
                }
    except Exception as e:
        return {
            'domain': domain,
            'error': str(e),
            'valid': False
        }

def scan_domain(domain):
    """Scan a domain and update database"""
    info = get_certificate_info(domain)

    if info['valid']:
        domain_obj = session.query(Domain).filter_by(url=domain).first()
        if not domain_obj:
            domain_obj = Domain(url=domain)

        domain_obj.last_scan = datetime.utcnow()
        domain_obj.expires_at = info['not_after']
        domain_obj.certificate_data = json.dumps(info, default=str)

        session.merge(domain_obj)
        session.commit()

        return info
    else:
        return info

@app.route('/')
def index():
    domains = session.query(Domain).all()
    current_time = datetime.utcnow()

    domain_data = []
    for domain in domains:
        days_until_expiry = (domain.expires_at - current_time).days if domain.expires_at else None
        domain_data.append({
            'id': domain.id,
            'url': domain.url,
            'last_scan': domain.last_scan,
            'expires_at': domain.expires_at,
            'days_until_expiry': days_until_expiry,
            'cert_data': json.loads(domain.certificate_data) if domain.certificate_data else None
        })

    return render_template('index.html', domains=domain_data)

@app.route('/add', methods=['POST'])
def add_domain():
    url = request.form.get('url')
    if url:
        # Check if domain already exists
        existing_domain = session.query(Domain).filter_by(url=url).first()
        if not existing_domain:
            # Add new domain
            new_domain = Domain(url=url)
            session.add(new_domain)
            session.commit()
    return redirect(url_for('index'))

@app.route('/remove/<int:id>', methods=['POST'])
def remove_domain(id):
    domain = session.query(Domain).get(id)
    if domain:
        session.delete(domain)
        session.commit()
    return redirect(url_for('index'))

@app.route('/scan/<int:id>', methods=['POST'])
def scan_domain_route(id):
    domain = session.query(Domain).get(id)
    if domain:
        scan_domain(domain.url)
    return redirect(url_for('index'))

@app.route('/certificate/<int:id>', methods=['GET'])
def certificate_details(id):
    domain = session.query(Domain).get(id)
    if domain and domain.certificate_data:
        cert_data = json.loads(domain.certificate_data)
        return render_template('certificate_details.html', cert_data=cert_data)
    return redirect(url_for('index'))

@app.route('/scan_all', methods=['POST'])
def scan_all():
    domains = session.query(Domain).all()
    for domain in domains:
        scan_domain(domain.url)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Initialize with test domains if empty
    if session.query(Domain).count() == 0:
        test_domains = ['google.com', 'yahoo.com']
        for domain in test_domains:
            if not session.query(Domain).filter_by(url=domain).first():
                new_domain = Domain(url=domain)
                session.add(new_domain)
                session.commit()
                scan_domain(domain)

    app.run(host='0.0.0.0', port=53468, debug=True)

