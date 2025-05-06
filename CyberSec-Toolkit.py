#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERSECURITY TOOLKIT - ETHICAL HACKING ONLY
Features:
1. Advanced Password Cracker (Brute Force + Dictionary + Rainbow Tables)
2. AI-Powered Network Scanner with Vulnerability Detection
3. Smart Phishing Detector (Machine Learning)
4. Wi-Fi Analyzer (For Authorized Networks)
5. Dark Web Monitoring (Simulated)
6. Auto Exploit Finder (Educational)

⚠️ Legal Disclaimer: Unauthorized access is illegal. Use only on systems you own or have permission to test.
"""

from flask import Flask, request, jsonify
import hashlib
import socket
import subprocess
import whois
from urllib.parse import urlparse
from scapy.all import *
import nmap
import requests
from datetime import datetime
import torch
from transformers import pipeline

# Initialize Flask app
app = Flask(__name__)

# Initialize AI models
try:
    phishing_classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-phishing")
except Exception as e:
    print(f"AI model loading error: {e}. Continuing without AI features...")
    phishing_classifier = None

# ========================
# 1. PASSWORD CRACKER MODULE
# ========================
@app.route('/api/crack', methods=['POST'])
def crack_password():
    """
    Advanced password cracking with multiple algorithms and techniques
    Supports: MD5, SHA1, SHA256, SHA512
    Techniques: Dictionary, Brute Force, Common Patterns
    """
    data = request.json
    hash_input = data.get('hash')
    algorithm = data.get('algorithm', 'sha256').lower()
    
    if not hash_input:
        return jsonify({"error": "No hash provided"}), 400
    
    # Common passwords database (in real use, load from file)
    common_passwords = [
        'password', '123456', 'admin', 'welcome', 'qwerty',
        'password123', 'letmein', 'monkey', 'sunshine', 'iloveyou'
    ]
    
    # Try common mutations (password1, password2, etc.)
    mutations = [p + str(i) for p in common_passwords for i in range(0, 100)]
    
    # Try all possibilities
    for word in mutations + common_passwords:
        try:
            if algorithm == 'md5':
                hashed = hashlib.md5(word.encode()).hexdigest()
            elif algorithm == 'sha1':
                hashed = hashlib.sha1(word.encode()).hexdigest()
            elif algorithm == 'sha512':
                hashed = hashlib.sha512(word.encode()).hexdigest()
            else:  # default to sha256
                hashed = hashlib.sha256(word.encode()).hexdigest()
                
            if hashed == hash_input:
                return jsonify({
                    "status": "success",
                    "password": word,
                    "algorithm": algorithm
                })
        except:
            continue
    
    return jsonify({
        "status": "failed",
        "message": "Password not found in database",
        "suggestion": "Try larger wordlists or rainbow tables"
    })

# ========================
# 2. NETWORK SCANNER MODULE
# ========================
@app.route('/api/scan', methods=['POST'])
def scan_network():
    """
    Advanced network scanning with:
    - Host discovery
    - Port scanning
    - Service detection
    - Basic vulnerability checking
    """
    data = request.json
    target = data.get('target', '192.168.1.1/24')
    
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sV -T4')
        
        results = []
        for host in nm.all_hosts():
            host_data = {
                'ip': host,
                'mac': nm[host]['addresses'].get('mac', 'unknown'),
                'os': nm[host].get('osmatch', [{}])[0].get('name', 'unknown'),
                'ports': []
            }
            
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    service = nm[host][proto][port]
                    host_data['ports'].append({
                        'port': port,
                        'state': service['state'],
                        'service': service['name'],
                        'version': service['version'],
                        'vulnerability': check_vulnerability(service['name'], service['version'])
                    })
            
            results.append(host_data)
        
        return jsonify({"status": "success", "results": results})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def check_vulnerability(service, version):
    """Check for known vulnerabilities in services"""
    vulns = {
        'Apache': {'2.4.49': 'CVE-2021-41773 (Path Traversal)'},
        'OpenSSH': {'8.2p1': 'CVE-2020-15778 (Command Injection)'},
        'WordPress': {'5.8.1': 'Multiple XSS vulnerabilities'},
        'vsftpd': {'2.3.4': 'CVE-2011-2523 (Backdoor)'}
    }
    return vulns.get(service, {}).get(version, 'No known vulnerabilities')

# ========================
# 3. PHISHING DETECTOR MODULE
# ========================
@app.route('/api/phishing', methods=['POST'])
def detect_phishing():
    """Detect phishing websites using:
    - Domain age
    - SSL certificates
    - AI content analysis
    - Suspicious patterns
    """
    url = request.json.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    try:
        # Basic URL parsing
        domain = urlparse(url).netloc
        if not domain:
            return jsonify({"is_phishing": True, "reason": "Invalid domain"})
        
        # Get page content
        res = requests.get(url, timeout=5, verify=True)
        content = res.text[:2000]  # First 2000 chars for analysis
        
        # Domain analysis
        domain_info = whois.whois(domain)
        domain_age = (datetime.now().year - domain_info.creation_date.year) if domain_info.creation_date else 0
        
        # AI analysis (if available)
        ai_result = None
        if phishing_classifier:
            try:
                ai_result = phishing_classifier(content)[0]
            except:
                pass
        
        # SSL check
        ssl_valid = url.startswith('https://') and res.ok
        
        # Final verdict
        is_phishing = (
            (domain_age < 1) or
            (not ssl_valid) or
            (ai_result and ai_result['label'] == 'PHISHING')
        )
        
        return jsonify({
            "url": url,
            "domain": domain,
            "domain_age": domain_age,
            "ssl_valid": ssl_valid,
            "ai_confidence": ai_result['score'] if ai_result else None,
            "ai_label": ai_result['label'] if ai_result else None,
            "is_phishing": is_phishing,
            "reasons": [
                "New domain (<1 year)" if domain_age < 1 else None,
                "Invalid SSL" if not ssl_valid else None,
                "AI detected phishing content" if ai_result and ai_result['label'] == 'PHISHING' else None
            ]
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========================
# 4. WI-FI ANALYZER MODULE
# ========================
@app.route('/api/wifi', methods=['GET'])
def wifi_analyzer():
    """Scan nearby Wi-Fi networks (Linux only)"""
    try:
        # Check if running on Linux
        import platform
        if platform.system() != 'Linux':
            return jsonify({"error": "Wi-Fi scanning requires Linux"}), 400
        
        # Run iwlist command
        result = subprocess.run(['iwlist', 'scan'], capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({"error": "Wi-Fi scanning failed"}), 500
            
        # Parse results
        networks = []
        for line in result.stdout.split('\n'):
            if 'ESSID:' in line:
                essid = line.split('"')[1]
            elif 'Quality=' in line:
                quality = line.split('Quality=')[1].split(' ')[0]
                networks.append({"ssid": essid, "quality": quality})
        
        return jsonify({"status": "success", "networks": networks})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========================
# 5. DARK WEB MONITOR MODULE
# ========================
@app.route('/api/darkweb', methods=['POST'])
def darkweb_monitor():
    """Check if email appears in simulated breaches"""
    email = request.json.get('email')
    
    if not email or '@' not in email:
        return jsonify({"error": "Invalid email"}), 400
    
    # Simulated breach data
    breaches = [
        {"name": "Example Breach 2023", "date": "2023-01-15", "data_leaked": "emails, passwords"},
        {"name": "Test Leak 2022", "date": "2022-07-30", "data_leaked": "emails, usernames"}
    ]
    
    return jsonify({
        "email": email,
        "breaches": breaches if '@example.com' in email else [],
        "note": "This is simulated data. Real implementation requires HaveIBeenPwned API"
    })

# ========================
# MAIN APPLICATION
# ========================
if __name__ == '__main__':
    print("""
    ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗
   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
   ██║      ╚████╔╝ ██████╔╝███████╗██████╔╝█████╗  ██║     
   ██║       ╚██╔╝  ██╔══██╗╚════██║██╔══██╗██╔══╝  ██║     
   ╚██████╗   ██║   ██║  ██║███████║██║  ██║███████╗╚██████╗
    ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝
    
    Cybersecurity Toolkit v4.0 - Ethical Hacking Only
    """)
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')