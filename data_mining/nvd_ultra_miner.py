import requests, pandas as pd, time, re

# 1. THE COMPLETE CWE MAP (Top 25 + Specialized)
CWE_MAP = {
    'CWE-89': 'SQLI', 'CWE-564': 'SQLI', 'CWE-943': 'SQLI', 'CWE-20': 'SQLI',
    'CWE-79': 'XSS', 'CWE-80': 'XSS', 'CWE-116': 'XSS',
    'CWE-78': 'RCE', 'CWE-94': 'RCE', 'CWE-91': 'RCE', 'CWE-502': 'RCE', 'CWE-119': 'RCE',
    'CWE-120': 'B_OVERFLOW', 'CWE-121': 'B_OVERFLOW', 'CWE-122': 'B_OVERFLOW', 'CWE-787': 'B_OVERFLOW',
    'CWE-400': 'DOS', 'CWE-770': 'DOS', 'CWE-730': 'DOS', 'CWE-404': 'DOS',
    'CWE-918': 'SSRF', 'CWE-22': 'PATH_TRAVERSAL', 'CWE-23': 'PATH_TRAVERSAL', 'CWE-35': 'PATH_TRAVERSAL',
    'CWE-269': 'PRIV_ESC', 'CWE-250': 'PRIV_ESC', 'CWE-284': 'PRIV_ESC', 'CWE-285': 'PRIV_ESC',
    'CWE-287': 'AUTH_FAILURE', 'CWE-255': 'AUTH_FAILURE', 'CWE-306': 'AUTH_FAILURE', 'CWE-522': 'AUTH_FAILURE',
    'CWE-200': 'INFO_DISCLOSURE', 'CWE-209': 'INFO_DISCLOSURE', 'CWE-212': 'INFO_DISCLOSURE',
    'CWE-352': 'CSRF', 'CWE-77': 'CMD_INJECTION', 'CWE-88': 'CMD_INJECTION'
}

# 2. THE EXPANDED KEYWORD MAP (The Safety Net)
KEYWORD_MAP = {
    'SQLI': ['sql injection', 'sqli', 'database query', 'select statements', 'nosql'],
    'XSS': ['cross-site scripting', 'xss', 'script injection', 'javascript execution', 'dom-based'],
    'RCE': ['remote code execution', 'rce', 'arbitrary code', 'shell execution', 'malicious code'],
    'B_OVERFLOW': ['buffer overflow', 'stack-based', 'heap-based', 'memory corruption', 'use-after-free'],
    'DOS': ['denial of service', 'dos', 'ddos', 'resource exhaustion', 'infinite loop', 'crash service'],
    'SSRF': ['server-side request forgery', 'ssrf', 'internal request', 'out-of-band'],
    'PATH_TRAVERSAL': ['directory traversal', 'path traversal', '../', 'file inclusion', 'lfi', 'rfi'],
    'PRIV_ESC': ['privilege escalation', 'privesc', 'root access', 'admin bypass', 'horizontal privilege'],
    'AUTH_FAILURE': ['broken authentication', 'credential theft', 'hardcoded password', 'session hijack'],
    'INFO_DISCLOSURE': ['information disclosure', 'data leakage', 'sensitive data', 'verbose error'],
    'CSRF': ['csrf', 'cross-site request forgery', 'xsrf'],
    'CMD_INJECTION': ['command injection', 'shell injection', 'os command']
}

def ultra_labeler(cve_item):
    desc = cve_item.get('descriptions', [{}])[0].get('value', '').lower()
    # 1. Official CWE Match
    for w in cve_item.get('weaknesses', []):
        for d in w.get('description', []):
            if d.get('value', '') in CWE_MAP: return CWE_MAP[d.get('value', '')]
    # 2. Keyword Match
    for cat, keys in KEYWORD_MAP.items():
        if any(k in desc for k in keys): return cat
    # 3. Deep Regex Match
    if re.search(r"SELECT.*FROM|UPDATE.*SET|INSERT.*INTO", desc, re.I): return "SQLI"
    if re.search(r"eval\(|exec\(|system\(|passthru\(", desc, re.I): return "RCE"
    return "OTHER"

def fetch_master_data(target=15000):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    data = []
    for i in range(0, target, 100):
        print(f"Mining records {i}...")
        try:
            r = requests.get(url, params={'resultsPerPage': 100, 'startIndex': i})
            if r.status_code == 200:
                for item in r.json().get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    label = ultra_labeler(cve)
                    data.append({'text': cve.get('descriptions', [{}])[0].get('value', ''), 'label': label})
            time.sleep(6) 
        except: continue
    
    df = pd.DataFrame(data).to_csv('nvd_master_2026.csv', index=False)
    print("Master Dataset Ready!")

fetch_master_data()