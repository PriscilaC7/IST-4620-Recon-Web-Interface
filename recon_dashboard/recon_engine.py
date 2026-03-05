import whois
import dns.resolver
import socket
import ssl
import requests
from urllib.parse import urlparse

def get_domain(url):
    parsed = urlparse(url)
    return parsed.netloc if parsed.netloc else parsed.path

def run_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

def run_dns(domain):
    records = {}
    for qtype in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, qtype)
            records[qtype] = [str(r) for r in answers]
        except Exception:
            records[qtype] = []
    return records

def check_ssl(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert['issuer'])['organizationName'],
                    "subject": dict(x[0] for x in cert['subject'])['commonName'],
                    "expires": cert['notAfter'],
                    "san": [x[1] for x in cert.get('subjectAltName', [])]
                }
    except Exception as e:
        return {"error": str(e)}

def check_headers_and_tech(url):
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing"),
            "Permissions-Policy": headers.get("Permissions-Policy", "Missing")
        }
        
        tech_fingerprint = {
            "Server": headers.get("Server", "Unknown"),
            "X-Powered-By": headers.get("X-Powered-By", "Unknown")
        }
        
        return {"security_headers": security_headers, "tech_fingerprint": tech_fingerprint}
    except Exception as e:
        return {"error": str(e)}

def fetch_robots_sitemap(url):
    base_url = f"https://{get_domain(url)}"
    results = {"robots.txt": "Not Found", "sitemap.xml": "Not Found"}
    
    try:
        r_robots = requests.get(f"{base_url}/robots.txt", timeout=5)
        if r_robots.status_code == 200:
            results["robots.txt"] = r_robots.text[:500] + "\n...(truncated)" if len(r_robots.text) > 500 else r_robots.text
            
        r_sitemap = requests.get(f"{base_url}/sitemap.xml", timeout=5)
        if r_sitemap.status_code == 200:
            results["sitemap.xml"] = "Found (Valid XML Sitemap)"
    except:
        pass
    
    return results

def perform_recon(url):
    domain = get_domain(url)
    return {
        "target": url,
        "domain": domain,
        "whois": run_whois(domain),
        "dns": run_dns(domain),
        "ssl": check_ssl(domain),
        "web_analysis": check_headers_and_tech(url),
        "public_files": fetch_robots_sitemap(url)
    }
