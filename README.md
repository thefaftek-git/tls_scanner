
# TLS Certificate Scanner

A web application to scan TLS certificates for a list of domains using Python with Flask.

## Features

- Add/remove domains via web interface
- Scan individual domains or all domains
- View certificate details with full metadata (SANs, CRLs, expiration dates, etc.)
- Expiration warnings and tracking

## Requirements

- Python 3.7+
- Flask
- SQLAlchemy
- cryptography
- idna
- requests

## Installation

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/thefaftek-git/tls_scanner.git
   cd tls_scanner
   ```

2. Build and run the Docker container:
   ```bash
   docker build -t tls_scanner .
   docker run -p 53468:53468 tls_scanner
   ```

3. Access the application at `http://localhost:53468`

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/thefaftek-git/tls_scanner.git
   cd tls_scanner
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   export PYTHONPATH=/path/to/tls_scanner
   python tls_certificate_scanner/app.py
   ```

4. Access the application at `http://localhost:53468`

## Testing

The application includes Playwright tests. To run the tests:

```bash
cd tls_certificate_scanner
python -m pytest tests/test_app.py -v
```

## Screenshots

![Main Interface](screenshots/main_interface.png)
![Certificate Details](screenshots/certificate_details.png)

## License

This project is licensed under the MIT License.

