"""SSL certificate generation for CryptoLabs Proxy."""

import subprocess
from pathlib import Path


def generate_self_signed_cert(ssl_dir: Path, domain: str):
    """Generate self-signed SSL certificate."""
    ssl_dir.mkdir(parents=True, exist_ok=True)
    
    cert_path = ssl_dir / "server.crt"
    key_path = ssl_dir / "server.key"
    
    subprocess.run([
        "openssl", "req", "-x509", "-nodes",
        "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-subj", f"/CN={domain}/O=CryptoLabs/C=ZA"
    ], capture_output=True)
    
    # Set permissions
    key_path.chmod(0o600)
    cert_path.chmod(0o644)
