import re
from urllib.parse import urlparse
from flask import Flask, render_template, request

app = Flask(__name__)

# List of sensitive keywords commonly exploited in phishing URLs
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'account', 'update', 'secure']


def scan_url(raw_url):
    """
    Performs rule-based heuristic security analysis on a submitted URL.
    Does NOT connect to, visit, or execute the target URL.
    """
    raw_url = raw_url.strip()
    if not raw_url:
        return None, "Please enter a URL to scan."

    # Normalize URL scheme for accurate parsing if omitted by the user
    has_scheme = raw_url.startswith(('http://', 'https://'))
    target_to_parse = raw_url if has_scheme else ('http://' + raw_url)

    try:
        parsed = urlparse(target_to_parse)
    except Exception as e:
        return None, f"Unable to parse URL: {str(e)}"

    domain = parsed.netloc.split(':')[0] if parsed.netloc else parsed.path.split('/')[0]
    if not domain:
        return None, "Invalid URL: Could not detect a valid domain name or hostname."

    protocol = parsed.scheme.upper() if has_scheme else "HTTP (Assumed / Unspecified)"

    checks = []
    risk_score = 0

    # ---------------------------------------------------------
    # Check 1: HTTPS Encryption Check
    # ---------------------------------------------------------
    if has_scheme and parsed.scheme.lower() == 'https':
        checks.append({
            'name': 'HTTPS Protocol',
            'status': 'PASS',
            'badge': 'pass',
            'details': 'Secure HTTPS encryption is active. Data transmission is protected.'
        })
    else:
        risk_score += 25
        checks.append({
            'name': 'HTTPS Protocol',
            'status': 'WARNING',
            'badge': 'warning',
            'details': 'URL does not use HTTPS. Traffic is unencrypted and vulnerable to interception.'
        })

    # ---------------------------------------------------------
    # Check 2: URL Length Analysis
    # ---------------------------------------------------------
    url_length = len(raw_url)
    if url_length <= 75:
        checks.append({
            'name': 'URL Length',
            'status': 'PASS',
            'badge': 'pass',
            'details': f'Normal length ({url_length} characters). Within standard 75-character threshold.'
        })
    else:
        risk_score += 15
        checks.append({
            'name': 'URL Length',
            'status': 'WARNING',
            'badge': 'warning',
            'details': f'Long URL detected ({url_length} characters). Often used to conceal redirection targets.'
        })

    # ---------------------------------------------------------
    # Check 3: IP Address Instead of Domain Name
    # ---------------------------------------------------------
    # Regular expression to match standard IPv4 address format (e.g. 192.168.1.1)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip_address = bool(re.match(ip_pattern, domain))

    if is_ip_address:
        risk_score += 30
        checks.append({
            'name': 'Domain Type (IP Check)',
            'status': 'WARNING',
            'badge': 'warning',
            'details': f'Raw IP address ({domain}) detected instead of a registered domain. Common indicator of phishing.'
        })
    else:
        checks.append({
            'name': 'Domain Type (IP Check)',
            'status': 'PASS',
            'badge': 'pass',
            'details': f'Valid domain name structure found ({domain}).'
        })

    # ---------------------------------------------------------
    # Check 4: '@' Symbol Obfuscation
    # ---------------------------------------------------------
    if '@' in raw_url:
        risk_score += 20
        checks.append({
            'name': 'Obfuscation Symbol (@)',
            'status': 'WARNING',
            'badge': 'warning',
            'details': "'@' symbol detected. Browsers ignore content preceding '@', which can trick users."
        })
    else:
        checks.append({
            'name': 'Obfuscation Symbol (@)',
            'status': 'PASS',
            'badge': 'pass',
            'details': "No '@' symbol detected."
        })

    # ---------------------------------------------------------
    # Check 5: Suspicious Phishing Keywords
    # ---------------------------------------------------------
    raw_lower = raw_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in raw_lower]

    if matched_keywords:
        risk_score += 20
        checks.append({
            'name': 'Suspicious Keywords',
            'status': 'WARNING',
            'badge': 'warning',
            'details': f'Sensitive keyword(s) detected: {", ".join(matched_keywords)}. Frequently targeted in phishing.'
        })
    else:
        checks.append({
            'name': 'Suspicious Keywords',
            'status': 'PASS',
            'badge': 'pass',
            'details': 'No sensitive credential or phishing keywords found.'
        })

    # Ensure risk score stays within 0 - 100 range
    risk_score = min(100, max(0, risk_score))

    # Determine risk category based on aggregate score
    if risk_score <= 20:
        risk_level = 'LOW'
        risk_badge = 'low'
        recommendation = 'The URL passed majority of heuristic checks and exhibits low initial risk.'
    elif risk_score <= 50:
        risk_level = 'MEDIUM'
        risk_badge = 'medium'
        recommendation = 'Exercise caution. The URL exhibits suspicious characteristics (e.g. unencrypted HTTP or sensitive keywords).'
    else:
        risk_level = 'HIGH'
        risk_badge = 'high'
        recommendation = 'High risk detected! Multiple security warnings were triggered. Avoid entering credentials.'

    result = {
        'entered_url': raw_url,
        'domain': domain,
        'protocol': protocol,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_badge': risk_badge,
        'recommendation': recommendation,
        'checks': checks,
        'checks_passed': sum(1 for c in checks if c['status'] == 'PASS'),
        'total_checks': len(checks)
    }

    return result, None


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    url_input = ''

    if request.method == 'POST':
        url_input = request.form.get('url', '').strip()
        result, error = scan_url(url_input)

    return render_template('index.html', result=result, error=error, url_input=url_input)


if __name__ == '__main__':
    # Local development server
    app.run(host='127.0.0.1', port=5000, debug=True)
