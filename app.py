from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import whois
import base64
import pickle
import ssl
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from dotenv import load_dotenv, find_dotenv

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# --- TENSORFLOW IMPORTS ---
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

app = Flask(__name__)
CORS(app) 

print("Initializing Enterprise Threat Intelligence System...")

# ==========================================
# SYSTEM CONFIGURATION
# ==========================================
env_path = find_dotenv()
if env_path != "":
    load_dotenv(env_path)

MODEL_PATH = 'xgboost_phishing_model.pkl'
VT_API_KEY = os.getenv('VT_API_KEY')
GSB_API_KEY = os.getenv('GSB_API_KEY')
CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

if not VT_API_KEY:
    print("WARNING: 'VT_API_KEY' missing in .env. VirusTotal will be bypassed.")
if not GSB_API_KEY:
    print("INFO: 'GSB_API_KEY' missing in .env. Google Safe Browsing will be bypassed.")

print("Loading XGBoost Core...")
try:
    xgb_model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"CRITICAL FAULT: Failed to load XGBoost: {e}")
    xgb_model = None

print("Loading TensorFlow Sequence Core & Tokenizer...")
try:
    lstm_model = load_model('phishing_lstm.h5')
    
    with open('char_tokenizer.pkl', 'rb') as handle:
        tokenizer = pickle.load(handle)
    print("System Online: Ensemble AI (XGB + TF) loaded successfully.")
except Exception as e:
    print(f"TF LOAD FAULT: {e}")
    print("WARNING: Running in degraded mode (XGBoost only).")
    lstm_model = None
    tokenizer = None

# Cache ChromeDriver path at startup (avoids re-downloading on every request)
print("Caching ChromeDriver path...")
try:
    CHROME_DRIVER_PATH = ChromeDriverManager().install()
    print(f"ChromeDriver cached: {CHROME_DRIVER_PATH}")
except Exception as e:
    print(f"WARNING: ChromeDriver cache failed: {e}")
    CHROME_DRIVER_PATH = None

def _get_chrome_options():
    """Return pre-configured Chrome options for headless screenshot capture."""
    chrome_options = Options()
    for opt in ["--headless", "--disable-gpu", "--no-sandbox", "--window-size=1280x800",
                 "--ignore-certificate-errors", "--disable-web-security",
                 "--disable-extensions", "--disable-dev-shm-usage",
                 "--disable-logging", "--disable-background-networking",
                 "--disable-default-apps", "--disable-sync",
                 "--disable-translate", "--mute-audio",
                 "--no-first-run", "--safebrowsing-disable-auto-update"]:
        chrome_options.add_argument(opt)
    chrome_options.add_argument(f'user-agent={CHROME_UA}')
    return chrome_options

# ==========================================
# TIER 3: PAYLOAD ANALYSIS + SCREENSHOT
# ==========================================
def analyze_payload(url):
    """Analyze URL payload for threats and capture a live screenshot.
    Also extracts the redirect chain from the initial HTTP request to avoid a duplicate call."""
    flags = []
    screenshot = None
    redirect_chain = []
    
    try:
        # Lightweight HTTP fetch for DOM analysis + redirect chain extraction
        res = requests.get(url, timeout=6, headers={'User-Agent': CHROME_UA}, verify=False, allow_redirects=True)
        
        # Extract redirect chain from the same response (avoids a second HTTP call)
        for r in res.history:
            p = urlparse(r.url)
            redirect_chain.append({'url': r.url, 'domain': p.netloc, 'status': r.status_code})
        p_final = urlparse(res.url)
        redirect_chain.append({'url': res.url, 'domain': p_final.netloc, 'status': res.status_code})
        
        soup = BeautifulSoup(res.text, 'html.parser')
        
        if not url.startswith('https'):
            if soup.find_all('input', type='password'):
                flags.append("Insecure Password Form")
        
        # Check for right-click blocking (informational only, not scored)
        page_lower = res.text.lower()
        if "contextmenu" in page_lower and "return false" in page_lower:
            flags.append("Inspection Blocked (No Right-Click)")
        
        # Selenium: Screenshot + Dynamic JS Analysis (using cached driver)
        if CHROME_DRIVER_PATH:
            try:
                service = ChromeService(CHROME_DRIVER_PATH)
                driver = webdriver.Chrome(service=service, options=_get_chrome_options())
                
                try:
                    driver.set_page_load_timeout(6)
                    driver.get(url)
                    time.sleep(0.8)  # Brief wait for JS render
                    
                    # Capture screenshot
                    screenshot = driver.get_screenshot_as_base64()
                    print(f"[Tier 3] Screenshot captured ({len(screenshot)} chars)")
                    
                    # Dynamic DOM analysis for JS-rendered password forms
                    if not url.startswith('https'):
                        dynamic_soup = BeautifulSoup(driver.page_source, 'html.parser')
                        if dynamic_soup.find_all('input', type='password'):
                            if "Insecure Password Form" not in flags:
                                flags.append("Insecure Password Form (JS Rendered)")
                finally:
                    driver.quit()
            except Exception as e:
                print(f"[Tier 3] Selenium failed: {e}")
        
        return {'flags': flags if flags else ["Clean DOM"], 'screenshot': screenshot, 'redirect_chain': redirect_chain}
        
    except requests.exceptions.Timeout:
        return {'flags': ["Timeout (Server non-responsive)"], 'screenshot': None, 'redirect_chain': []}
    except requests.exceptions.SSLError:
        return {'flags': ["Invalid SSL Certificate"], 'screenshot': None, 'redirect_chain': []}
    except requests.exceptions.ConnectionError:
        return {'flags': ["Connection Refused"], 'screenshot': None, 'redirect_chain': []}
    except Exception as e:
        print(f"[Tier 3] Payload scan failed: {e}")
        return {'flags': ["Scan Failed"], 'screenshot': None, 'redirect_chain': []}

# ==========================================
# TIER 2: OSINT & INTELLIGENCE
# ==========================================
def check_virustotal(url):
    """Query VirusTotal for malicious/suspicious flags."""
    if not VT_API_KEY: return 0
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        response = requests.get(api_url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0) + stats.get('suspicious', 0)
        return 0
    except: return 0

def check_domain_age(domain):
    """Check domain age via VirusTotal API, fallback to WHOIS."""
    # --- Method 1: VirusTotal Domain Info (most reliable) ---
    if VT_API_KEY:
        try:
            clean_domain = domain.split(':')[0].strip().lower()
            api_url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}"
            headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
            response = requests.get(api_url, headers=headers, timeout=5)
            if response.status_code == 200:
                attrs = response.json().get('data', {}).get('attributes', {})
                creation_ts = attrs.get('creation_date')
                if creation_ts:
                    creation_dt = datetime.fromtimestamp(creation_ts)
                    age_days = (datetime.now() - creation_dt).days
                    print(f"[OSINT] Domain age from VirusTotal: {age_days} days")
                    return age_days
                whois_data = attrs.get('whois', '')
                if whois_data:
                    import re as _re
                    match = _re.search(r'Creation Date:\s*(.+)', whois_data, _re.IGNORECASE)
                    if match:
                        from dateutil import parser as dateutil_parser
                        creation_dt = dateutil_parser.parse(match.group(1).strip())
                        age_days = (datetime.now() - creation_dt).days
                        print(f"[OSINT] Domain age from VT WHOIS text: {age_days} days")
                        return age_days
        except Exception as e:
            print(f"[OSINT] VT domain age lookup failed: {e}")

    # --- Method 2: Fallback to python-whois ---
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if type(creation_date) is list: creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            print(f"[OSINT] Domain age from WHOIS fallback: {age_days} days")
            return age_days
    except Exception as e:
        print(f"[OSINT] WHOIS fallback failed: {e}")
    return -1

def check_ssl_certificate(domain):
    """Extract SSL certificate details from the domain."""
    try:
        clean_domain = domain.split(':')[0].strip()
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                issuer_parts = dict(x[0] for x in cert.get('issuer', []))
                subject_parts = dict(x[0] for x in cert.get('subject', []))
                
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days
                cert_age_days = (datetime.now() - not_before).days
                
                return {
                    'issuer': issuer_parts.get('organizationName', issuer_parts.get('commonName', 'Unknown')),
                    'subject': subject_parts.get('commonName', 'Unknown'),
                    'valid_from': not_before.strftime('%b %d, %Y'),
                    'valid_until': not_after.strftime('%b %d, %Y'),
                    'days_until_expiry': days_until_expiry,
                    'cert_age_days': cert_age_days,
                    'is_expired': days_until_expiry < 0,
                    'protocol': ssock.version()
                }
    except Exception as e:
        print(f"[SSL] Certificate check failed: {e}")
        return None

def check_redirect_chain(url):
    """Track the full redirect chain of a URL."""
    try:
        response = requests.get(url, headers={'User-Agent': CHROME_UA}, 
                               timeout=8, verify=False, allow_redirects=True)
        chain = []
        for r in response.history:
            p = urlparse(r.url)
            chain.append({'url': r.url, 'domain': p.netloc, 'status': r.status_code})
        p_final = urlparse(response.url)
        chain.append({'url': response.url, 'domain': p_final.netloc, 'status': response.status_code})
        return chain
    except Exception as e:
        print(f"[Redirect] Chain check failed: {e}")
        return [{'url': url, 'domain': urlparse(url).netloc or url, 'status': 0}]

def check_google_safebrowsing(url):
    """Check URL against Google Safe Browsing API v4."""
    if not GSB_API_KEY:
        return None
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
        body = {
            "client": {"clientId": "phishing-url-checker", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(api_url, json=body, timeout=5)
        if response.status_code == 200:
            matches = response.json().get('matches', [])
            return len(matches)
        return 0
    except Exception as e:
        print(f"[GSB] Safe Browsing check failed: {e}")
        return None



# ==========================================
# TIER 1: HEURISTICS
# ==========================================
def check_heuristics(url, features):
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme.lower() not in ['http', 'https']: return "CRITICAL RISK", 100.0
    if features['has_ip'] == 1: return "CRITICAL RISK", 98.0
    if features['qty_at'] > 0 or features['qty_tilde'] > 0 or features['qty_asterisk'] > 2: return "CRITICAL RISK", 85.0
    
    domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower()
    
    sketchy_keywords = ['login', 'update', 'secure', 'account', 'verify', 'auth', 'support']
    brands = ['google', 'apple', 'paypal', 'microsoft', 'amazon', 'netflix', 'meta']
    
    has_brand = any(b in domain for b in brands)
    has_sketch = any(k in domain for k in sketchy_keywords)
    if has_brand and has_sketch: 
        return "CRITICAL RISK", 95.0
        
    if domain.count('-') >= 3: 
        return "SUSPICIOUS", 75.0
        
    high_risk_tlds = ['.xyz', '.top', '.pw', '.tk', '.cc', '.ru', '.cn']
    if any(domain.endswith(tld) for tld in high_risk_tlds): 
        return "SUSPICIOUS", 65.0
        
    if len(url) > 100: return "SUSPICIOUS", 60.0
    return None, None

def extract_features(url):
    features = {'url_length': len(url), 'qty_dot': url.count('.'), 'qty_hyphen': url.count('-'), 'qty_underline': url.count('_'), 'qty_slash': url.count('/'), 'qty_questionmark': url.count('?'), 'qty_equal': url.count('='), 'qty_at': url.count('@'), 'qty_and': url.count('&'), 'qty_exclamation': url.count('!'), 'qty_space': url.count(' '), 'qty_tilde': url.count('~'), 'qty_comma': url.count(','), 'qty_plus': url.count('+'), 'qty_asterisk': url.count('*'), 'qty_hashtag': url.count('#'), 'qty_dollar': url.count('$'), 'qty_percent': url.count('%')}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        features['domain_length'] = len(domain)
        features['domain_qty_dot'] = domain.count('.')
    except:
        features['domain_length'] = 0; features['domain_qty_dot'] = 0
    
    ipv4_pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])')
    features['has_ip'] = 1 if ipv4_pattern.search(url) else 0
    return features

# ==========================================
# ROUTING & AI FUSION
# ==========================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        
        if not url: return jsonify({'error': 'No URL provided'}), 400

        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url

        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        
        features_dict = extract_features(url)
        features_df = pd.DataFrame([features_dict])

        # --- TIER 1: HEURISTICS ---
        h_status, h_score = check_heuristics(url, features_dict)
        if h_status:
            # Still gather quick OSINT for heuristic blocks
            ssl_info = None
            redirect_chain = [{'url': url, 'domain': domain, 'status': 0}]
            try:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    ssl_future = executor.submit(check_ssl_certificate, domain)
                    redir_future = executor.submit(check_redirect_chain, url)
                    ssl_info = ssl_future.result(timeout=6)
                    redirect_chain = redir_future.result(timeout=9)
            except: pass
            
            return jsonify({
                'url': url, 'risk_score': h_score, 'status': h_status,
                'lexical_features': features_dict,
                'vt_flags': "Bypassed", 'domain_age': "Bypassed",
                'payload_status': "Bypassed (Heuristics Block)",
                'screenshot': None,
                'ssl_info': ssl_info,
                'redirect_chain': redirect_chain,
                'gsb_flags': None,
                'score_breakdown': {
                    'heuristics': h_score, 'ml_ensemble': 0,
                    'virustotal': 0, 'domain_age': 0, 'payload': 0, 'ssl': 0
                }
            })

        # --- TIER 1.5: ENSEMBLE AI (XGBOOST + TENSORFLOW) ---
        xgb_risk_score = 0.0
        if xgb_model:
            xgb_prob = xgb_model.predict_proba(features_df)[0][1]
            xgb_risk_score = float(round(xgb_prob * 100, 2))
        
        lstm_risk_score = 0.0
        if lstm_model and tokenizer:
            try:
                seq = tokenizer.texts_to_sequences([url])
                padded_seq = pad_sequences(seq, maxlen=150, padding='post', truncating='post')
                lstm_prob = lstm_model.predict(padded_seq, verbose=0)[0][0]
                lstm_risk_score = float(round(lstm_prob * 100, 2))
            except Exception as e:
                print(f"TF Inference Fault: {e}")

        ml_risk_score = round((xgb_risk_score + lstm_risk_score) / 2, 2)

        print("XGBoost Risk Score:", xgb_risk_score)
        print("Bi-LSTM Risk Score:", lstm_risk_score)
        print("Combined ML Risk Score:", ml_risk_score)

        # --- TIER 2 & 3: PARALLEL OSINT + PAYLOAD ---
        # Run all network checks in parallel for speed
        # Note: redirect chain is now extracted from the payload request (same HTTP call)
        vt_flags = 0
        domain_age = -1
        ssl_info = None
        redirect_chain = [{'url': url, 'domain': domain, 'status': 0}]
        gsb_flags = None
        payload_result = {'flags': ['Scan Failed'], 'screenshot': None, 'redirect_chain': []}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            vt_future = executor.submit(check_virustotal, url)
            age_future = executor.submit(check_domain_age, domain)
            ssl_future = executor.submit(check_ssl_certificate, domain)
            gsb_future = executor.submit(check_google_safebrowsing, url)
            payload_future = executor.submit(analyze_payload, url)
            
            try: vt_flags = vt_future.result(timeout=8) or 0
            except: pass
            try: domain_age = age_future.result(timeout=8) or -1
            except: pass
            try: ssl_info = ssl_future.result(timeout=6)
            except: pass
            try: gsb_flags = gsb_future.result(timeout=6)
            except: pass
            try: payload_result = payload_future.result(timeout=12) or payload_result
            except: pass
        
        payload_flags = payload_result['flags']
        screenshot = payload_result.get('screenshot')
        # Use redirect chain from the payload request (avoids duplicate HTTP call)
        payload_redirects = payload_result.get('redirect_chain', [])
        if payload_redirects:
            redirect_chain = payload_redirects
        
        # --- SCORE FUSION ---
        final_score = ml_risk_score
        score_breakdown = {
            'heuristics': 0, 'ml_ensemble': ml_risk_score,
            'virustotal': 0, 'domain_age': 0, 'payload': 0, 'ssl': 0
        }
        
        # Payload scoring (only insecure password forms affect score)
        if "Insecure Password Form" in payload_flags:
            final_score = max(final_score, 90.0) 
            score_breakdown['payload'] = 90.0
        # Note: "Inspection Blocked (No Right-Click)" is informational only — 
        # legitimate sites like YouTube/Netflix disable right-click on media.
            
        # VirusTotal scoring
        if vt_flags >= 3:
            final_score = max(final_score, 99.0)
            score_breakdown['virustotal'] = 99.0
        elif vt_flags > 0:
            score_breakdown['virustotal'] = min(vt_flags * 33, 99)
            
        # Domain age scoring
        if domain_age != -1 and domain_age < 30:
            final_score = max(final_score, 80.0)
            score_breakdown['domain_age'] = 80.0
            
        # SSL scoring
        if ssl_info:
            if ssl_info['is_expired']:
                final_score = max(final_score, 70.0)
                score_breakdown['ssl'] = 70.0
            elif ssl_info['cert_age_days'] < 7:
                score_breakdown['ssl'] = 40.0
        elif url.startswith('https'):
            score_breakdown['ssl'] = 50.0
            
        # Redirect chain scoring
        if len(redirect_chain) > 3:
            final_score = max(final_score, 60.0)
            score_breakdown['heuristics'] = max(score_breakdown['heuristics'], 60.0)
        
        # Google Safe Browsing scoring
        if gsb_flags and gsb_flags > 0:
            final_score = max(final_score, 99.0)
            score_breakdown['virustotal'] = max(score_breakdown['virustotal'], 99.0)



        if final_score > 75: status = "CRITICAL RISK"
        elif final_score > 40: status = "SUSPICIOUS"
        else: status = "SAFE"

        age_display = f"{domain_age} days" if domain_age != -1 else "Unknown"

        return jsonify({
            'url': url, 'risk_score': final_score, 'status': status,
            'lexical_features': features_dict,
            'vt_flags': vt_flags, 'domain_age': age_display,
            'payload_status': ", ".join(payload_flags),
            'screenshot': screenshot,
            'ssl_info': ssl_info,
            'redirect_chain': redirect_chain,
            'gsb_flags': gsb_flags,
            'score_breakdown': score_breakdown
        })
        
    except Exception as e:
        print(f"Backend Traceback: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server fault: {str(e)}'}), 500

@app.route('/analyze-bulk', methods=['POST'])
def analyze_bulk():
    """Analyze multiple URLs in a quick batch (ML + VT only, no payload/screenshot)."""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        urls = urls[:10]  # Cap at 10
        results = []
        
        for url in urls:
            url = url.strip()
            if not url:
                continue
            try:
                parsed = urlparse(url)
                domain = parsed.netloc if parsed.netloc else parsed.path
                features_dict = extract_features(url)
                features_df = pd.DataFrame([features_dict])
                
                h_status, h_score = check_heuristics(url, features_dict)
                if h_status:
                    results.append({'url': url, 'risk_score': h_score, 'status': h_status})
                    continue
                
                xgb_risk_score = 0.0
                if xgb_model:
                    xgb_prob = xgb_model.predict_proba(features_df)[0][1]
                    xgb_risk_score = float(round(xgb_prob * 100, 2))
                
                lstm_risk_score = 0.0
                if lstm_model and tokenizer:
                    try:
                        seq = tokenizer.texts_to_sequences([url])
                        padded_seq = pad_sequences(seq, maxlen=150, padding='post', truncating='post')
                        lstm_prob = lstm_model.predict(padded_seq, verbose=0)[0][0]
                        lstm_risk_score = float(round(lstm_prob * 100, 2))
                    except: pass
                
                ml_score = round((xgb_risk_score + lstm_risk_score) / 2, 2)
                vt = check_virustotal(url)
                
                final_score = ml_score
                if vt >= 3: final_score = max(final_score, 99.0)
                
                status = "SAFE"
                if final_score > 75: status = "CRITICAL RISK"
                elif final_score > 40: status = "SUSPICIOUS"
                
                results.append({'url': url, 'risk_score': round(final_score, 1), 'status': status})
                
            except Exception as e:
                results.append({'url': url, 'risk_score': -1, 'status': 'ERROR'})
        
        return jsonify({'results': results})
        
    except Exception as e:
        return jsonify({'error': f'Bulk analysis failed: {str(e)}'}), 500

if __name__ == '__main__':
    local_lan_ip = '127.0.0.1'
    try:
        hostname = socket.gethostname()
        _, _, addrs = socket.gethostbyname_ex(hostname)
        lan_addrs = [a for a in addrs if not a.startswith('127.') and not a.startswith('10.2.')]
        if lan_addrs:
            local_lan_ip = lan_addrs[0]
        else:
            for a in addrs:
                if not a.startswith('127.'):
                    local_lan_ip = a
                    break
    except Exception:
        pass

    mobile_url = f"http://{local_lan_ip}:5001"
    
    print("\n" + "="*60)
    print("🚀 PHISHING THREAT INTELLIGENCE PLATFORM ONLINE")
    print("="*60)
    print(f"💻 Local Computer Access : http://localhost:5001")
    print(f"📱 Mobile / Phone Access  : {mobile_url}")
    print("="*60)
    print("📱 SCAN THIS QR CODE WITH YOUR PHONE CAMERA TO OPEN THE APP:")
    print("="*60)
    try:
        import qrcode
        qr = qrcode.QRCode()
        qr.add_data(mobile_url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except Exception as e:
        print(f"(QR code generator unavailable: {e})")
    print("="*60)
    print("💡 MOBILE TROUBLESHOOTING TIPS:")
    print(" 1. Ensure phone is on the SAME WI-FI network as this Mac.")
    print(" 2. Type 'http://' explicitly on mobile browser (do NOT use https://).")
    print(" 3. If using a VPN (e.g. WARP, Tailscale), temporarily turn it off.")
    print("="*60 + "\n")

    app.run(host='0.0.0.0', debug=True, port=5001)