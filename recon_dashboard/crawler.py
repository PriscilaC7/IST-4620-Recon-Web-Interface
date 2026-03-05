import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import time

def get_robots_parser(base_url):
    rp = RobotFileParser()
    rp.set_url(urljoin(base_url, "/robots.txt"))
    try:
        rp.read()
    except:
        pass
    return rp

def passive_crawl(start_url, max_pages=5):
    domain = urlparse(start_url).netloc
    base_url = f"https://{domain}"
    
    rp = get_robots_parser(base_url)
    
    visited = set()
    to_visit = [start_url]
    assets = {"pages": set(), "scripts": set(), "external": set()}
    
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        
        if url in visited or not rp.can_fetch("*", url):
            continue
            
        visited.add(url)
        assets["pages"].add(url)
        
        try:
            # Rate limiting
            time.sleep(1) 
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                if urlparse(full_url).netloc == domain:
                    if full_url not in visited:
                        to_visit.append(full_url)
                else:
                    if full_url.startswith('http'):
                        assets["external"].add(full_url)
                        
            # Extract scripts
            for script in soup.find_all('script', src=True):
                assets["scripts"].add(urljoin(url, script['src']))
                
        except Exception:
            continue
            
    # Convert sets to lists for JSON serialization
    return {k: list(v) for k, v in assets.items()}
