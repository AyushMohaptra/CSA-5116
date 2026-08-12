import json
import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Helper function to serialize certificate fields for signing/verification
def get_cert_bytes(cert_dict):
    tbs_data = {
        "subject": cert_dict["subject"],
        "issuer": cert_dict["issuer"],
        "public_key": cert_dict["public_key_pem"],
        "not_before": cert_dict["not_before"],
        "not_after": cert_dict["not_after"],
        "is_ca": cert_dict["is_ca"]
    }
    # Standardize serialization using sorted keys
    return json.dumps(tbs_data, sort_keys=True).encode('utf-8')

# Helper function to sign a certificate dictionary
def sign_certificate(cert_dict, issuer_private_key):
    data = get_cert_bytes(cert_dict)
    h = SHA256.new(data)
    signature = pkcs1_15.new(issuer_private_key).sign(h)
    cert_dict["signature"] = signature

# Helper function to verify a certificate's signature
def verify_signature(cert_dict, issuer_public_key):
    if "signature" not in cert_dict or cert_dict["signature"] is None:
        return False
    data = get_cert_bytes(cert_dict)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(issuer_public_key).verify(h, cert_dict["signature"])
        return True
    except (ValueError, TypeError):
        return False

# Master certificate chain verification function
def verify_certificate_chain(chain, root_cert, crl_set, current_time=None):
    if current_time is None:
        current_time = time.time()
        
    print(f"[*] Starting Chain Verification (Length: {len(chain)}). Current Time: {time.ctime(current_time)}")
    
    # 1. Trust Anchor Validation
    root_pub = RSA.import_key(root_cert["public_key_pem"])
    if not verify_signature(root_cert, root_pub):
        return False, "Root CA signature is invalid (not self-signed)."
    if root_cert["subject"] != root_cert["issuer"]:
        return False, "Root CA is not self-signed."
    if not root_cert["is_ca"]:
        return False, "Root CA lacks CA constraint."
        
    print("    [+] Trusted Root CA verified successfully.")
    
    # Validate chain link-by-link
    parent_cert = root_cert
    for idx, cert in enumerate(chain):
        print(f"    [*] Verifying Certificate {idx + 1}: '{cert['subject']}' issued by '{cert['issuer']}'")
        
        # A. Issuer match check
        if cert["issuer"] != parent_cert["subject"]:
            return False, f"Issuer mismatch: Certificate issued by '{cert['issuer']}' but expected '{parent_cert['subject']}'."
            
        # B. CA Constraint check
        if not parent_cert["is_ca"]:
            return False, f"Constraint Violation: Issuer '{parent_cert['subject']}' is not a CA."
            
        # C. Signature check
        parent_pub = RSA.import_key(parent_cert["public_key_pem"])
        if not verify_signature(cert, parent_pub):
            return False, f"Signature Verification Failed for certificate '{cert['subject']}'."
            
        # D. Validity period check
        if current_time < cert["not_before"]:
            return False, f"Validity Error: '{cert['subject']}' is not yet valid."
        if current_time > cert["not_after"]:
            return False, f"Validity Error: '{cert['subject']}' has expired."
            
        # E. Revocation check
        if cert["subject"] in crl_set:
            return False, f"Revocation Error: '{cert['subject']}' has been revoked."
            
        print("        [+] Verified.")
        parent_cert = cert
        
    return True, "Certificate chain is VALID and TRUSTED."

def run_experiment():
    print("======================================================================")
    print("Experiment 3: Simulation of Certificate Chain Validation")
    print("======================================================================\n")
    
    print("[*] Generating RSA key pairs...")
    root_priv = RSA.generate(2048)
    root_pub_pem = root_priv.publickey().export_key().decode('utf-8')
    
    inter_priv = RSA.generate(2048)
    inter_pub_pem = inter_priv.publickey().export_key().decode('utf-8')
    
    entity_priv = RSA.generate(2048)
    entity_pub_pem = entity_priv.publickey().export_key().decode('utf-8')
    
    unrelated_priv = RSA.generate(2048)
    print("    Keys generated successfully.\n")
    
    now = time.time()
    one_hour = 3600
    one_year = 365 * 24 * one_hour
    
    # 1. Root CA Certificate
    root_cert = {
        "subject": "Global Trust Root CA",
        "issuer": "Global Trust Root CA",
        "public_key_pem": root_pub_pem,
        "not_before": now - one_year,
        "not_after": now + one_year,
        "is_ca": True
    }
    sign_certificate(root_cert, root_priv)
    
    # 2. Intermediate CA Certificate
    inter_cert = {
        "subject": "Secure IT Intermediate CA",
        "issuer": "Global Trust Root CA",
        "public_key_pem": inter_pub_pem,
        "not_before": now - one_year,
        "not_after": now + one_year,
        "is_ca": True
    }
    sign_certificate(inter_cert, root_priv)
    
    # 3. End-Entity Certificate
    entity_cert = {
        "subject": "web-server.enterprise.com",
        "issuer": "Secure IT Intermediate CA",
        "public_key_pem": entity_pub_pem,
        "not_before": now - one_hour,
        "not_after": now + one_hour,
        "is_ca": False
    }
    sign_certificate(entity_cert, inter_priv)
    
    crl_list = set()
    
    # Case 1: Valid Chain Validation
    print("--- CASE 1: Validating a Correct Certificate Chain ---")
    chain = [inter_cert, entity_cert]
    success, msg = verify_certificate_chain(chain, root_cert, crl_list)
    print(f"--> Chain Verification Result: {success} | Message: {msg}\n")
    
    # Case 2: Expired Certificate Detection
    print("--- CASE 2: Validating an Expired Certificate Chain ---")
    expired_cert = {
        "subject": "expired-server.enterprise.com",
        "issuer": "Secure IT Intermediate CA",
        "public_key_pem": entity_pub_pem,
        "not_before": now - 2 * one_hour,
        "not_after": now - one_hour,
        "is_ca": False
    }
    sign_certificate(expired_cert, inter_priv)
    
    chain_expired = [inter_cert, expired_cert]
    success, msg = verify_certificate_chain(chain_expired, root_cert, crl_list)
    print(f"--> Chain Verification Result: {success} | Message: {msg}\n")
    
    # Case 3: Revoked Certificate Detection
    print("--- CASE 3: Validating a Revoked Certificate Chain ---")
    revoked_crl = {"web-server.enterprise.com"}
    success, msg = verify_certificate_chain(chain, root_cert, revoked_crl)
    print(f"--> Chain Verification Result: {success} | Message: {msg}\n")
    
    # Case 4: Signature Mismatch (Tampering Detection)
    print("--- CASE 4: Validating a Chain with Signature Mismatch ---")
    tampered_cert = {
        "subject": "malicious-server.enterprise.com",
        "issuer": "Secure IT Intermediate CA",
        "public_key_pem": entity_pub_pem,
        "not_before": now - one_hour,
        "not_after": now + one_hour,
        "is_ca": False
    }
    sign_certificate(tampered_cert, unrelated_priv) # signed by unrelated private key
    
    chain_tampered = [inter_cert, tampered_cert]
    success, msg = verify_certificate_chain(chain_tampered, root_cert, crl_list)
    print(f"--> Chain Verification Result: {success} | Message: {msg}\n")
    
    # Case 5: Path Constraint Violation
    print("--- CASE 5: Constraint Violation (Non-CA used as issuer) ---")
    fake_issued_cert = {
        "subject": "fake-client.enterprise.com",
        "issuer": "web-server.enterprise.com",
        "public_key_pem": entity_pub_pem,
        "not_before": now - one_hour,
        "not_after": now + one_hour,
        "is_ca": False
    }
    sign_certificate(fake_issued_cert, entity_priv)
    
    chain_constraint = [inter_cert, entity_cert, fake_issued_cert]
    success, msg = verify_certificate_chain(chain_constraint, root_cert, crl_list)
    print(f"--> Chain Verification Result: {success} | Message: {msg}\n")
    print("======================================================================\n")

if __name__ == "__main__":
    run_experiment()
