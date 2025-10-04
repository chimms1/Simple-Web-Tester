#!/usr/bin/env python3
"""
vulnerability_scanner.py
Active vulnerability scanner for CSRF and Reflected XSS with automatic login.

Usage:
  python main.py --base http://localhost:3000/ --username bee --password buggy

WARNING: This script actively submits state-changing and probe requests.
Only run on systems you own or have explicit permission to test.
"""

import argparse
import time
import re
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs, urlencode
from collections import deque
import requests
from bs4 import BeautifulSoup
import difflib
import json

# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certs
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# --- Heuristics and Payloads ---
COMMON_CSRF_NAMES = [
    'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token', '__requestverificationtoken',
    'xsrf-token', 'xsrf_token', 'XSRF-TOKEN', 'csrf', '_csrf', '_csrf_token', 'token'
]
STATE_CHANGE_KEYWORDS = ['delete', 'remove', 'destroy', 'logout', 'revoke', 'disable', 'update', 'edit', 'create', 'post', 'withdraw', 'changepassword', 'addfunds']

# Payloads designed to break out of HTML attributes and script contexts.
XSS_PAYLOADS = [
    '"><script>alert("XSS-Scanner-Probe")</script>',
    "'><script>alert('XSS-Scanner-Probe')</script>",
    '<img src=x onerror=alert("XSS-Scanner-Probe")>',
    '"><svg/onload=alert`XSS-Scanner-Probe`>'
]

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0'

# --- Utilities ---
def normalize_url(url):
    """Removes URL fragment and standardizes."""
    u, _ = urldefrag(url)
    return u

def same_domain(a, b):
    return urlparse(a).netloc == urlparse(b).netloc

def looks_like_state_changing_url(href):
    """More precise check for state-changing keywords in URLs."""
    if not href:
        return False
    href_lower = href.lower()
    for kw in STATE_CHANGE_KEYWORDS:
        if kw in href_lower:
            return True
    # Look for patterns like action=delete, op=remove, etc. for better accuracy
    if '?' in href:
        q = href.split('?', 1)[1]
        if re.search(r'\b(action|cmd|op)=(' + '|'.join(STATE_CHANGE_KEYWORDS) + r')\b', q, re.IGNORECASE):
            return True
    return False

def is_likely_csrf_token_name(name):
    if not name:
        return False
    lname = name.lower()
    for common in COMMON_CSRF_NAMES:
        if common in lname:
            return True
    if lname.startswith('x-csrf') or lname.startswith('x-xsrf') or lname.startswith('__requestverificationtoken'):
        return True
    return False

def simple_response_similarity(a_text, b_text):
    if a_text is None or b_text is None:
        return False
    la, lb = len(a_text), len(b_text)
    if la == 0 and lb == 0:
        return True
    if max(la, lb) == 0:
        return False
    if abs(la - lb) / max(la, lb) > 0.20:
        return False
    sa = ' '.join(a_text.split())
    sb = ' '.join(b_text.split())
    seq = difflib.SequenceMatcher(None, sa, sb)
    return seq.quick_ratio() > 0.92

def get_links_and_forms(html, base):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        full = urljoin(base, a['href'].strip())
        links.add(normalize_url(full))
    forms = soup.find_all('form')
    return links, forms

def extract_form_action(form, current_url):
    action = form.get('action')
    if not action:
        return current_url
    return normalize_url(urljoin(current_url, action))

def gather_hidden_inputs(form):
    data = {}
    for inp in form.find_all('input'):
        name = inp.get('name')
        if not name:
            continue
        value = inp.get('value', '')
        data[name] = value
    return data

# --- Login Helpers ---
def looks_like_login_form(form):
    uname_fields = ['username','user','email','login','userid']
    pword_fields = ['password','pass']
    input_names = [(inp.get('name') or '').lower() for inp in form.find_all('input')]
    has_uname = any(u in input_names for u in uname_fields)
    has_pword = any(p in input_names for p in pword_fields)
    return has_uname and has_pword

def attempt_form_login(session, page_url, username, password):
    try:
        page_resp = session.get(page_url, timeout=20)
        soup = BeautifulSoup(page_resp.text, 'html.parser')
    except requests.exceptions.RequestException as e:
        print(f"[!] Could not fetch login page {page_url}: {e}")
        return None
    forms = soup.find_all('form')
    candidate = None
    uname_names = ['username','user','email','login','userid']
    pword_names = ['password','pass']
    for f in forms:
        input_names = [(inp.get('name') or '').lower() for inp in f.find_all('input')]
        if any(u in input_names for u in uname_names) and any(p in input_names for p in pword_names):
            candidate = f
            break
    if candidate is None and forms:
        candidate = forms[0]
    elif candidate is None:
        return None
    data = gather_hidden_inputs(candidate)
    ufield = pfield = None
    for inp in candidate.find_all('input'):
        name = inp.get('name') or inp.get('id') or ''
        lname = name.lower()
        if any(u in lname for u in uname_names) and ufield is None:
            ufield = name
        if any(p in lname for p in pword_names) and pfield is None:
            pfield = name
    ufield = ufield or 'username'
    pfield = pfield or 'password'
    data[ufield] = username
    data[pfield] = password
    action = extract_form_action(candidate, page_url)
    method = (candidate.get('method') or 'post').lower()
    try:
        resp = session.request(method, action, data=data, timeout=20, allow_redirects=True)
        if resp.status_code < 400:
            return resp
    except requests.exceptions.RequestException as e:
        print(f"[!] Login request to {action} failed: {e}")
        return None
    return None

# --- CSRF Active Test Helpers ---
def build_baseline_payload(form):
    data = {}
    for inp in form.find_all('input'):
        name = inp.get('name')
        if not name: continue
        itype = (inp.get('type') or 'text').lower()
        val = inp.get('value','')
        if itype in ('hidden','submit'): data[name] = val
        elif itype in ('text','email','search','tel'): data[name] = val or 'test'
        elif itype == 'password': data[name] = val or 'TestPass123!'
        elif itype == 'number': data[name] = val or '1'
        else: data[name] = val
    for ta in form.find_all('textarea'):
        name = ta.get('name')
        if name: data[name] = ta.text or 'test'
    for s in form.find_all('select'):
        name = s.get('name')
        if not name: continue
        opt = s.find('option', selected=True) or s.find('option')
        data[name] = opt.get('value') or opt.text if opt else '1'
    return data

def build_stripped_payload(baseline):
    return {k:v for k,v in baseline.items() if not is_likely_csrf_token_name(k)}

def attempt_active_csrf_test(session, form, page_url):
    action = extract_form_action(form, page_url)
    method = (form.get('method') or 'post').lower()
    if method not in ('post','put','patch','delete'): return None
    baseline = build_baseline_payload(form)
    if not baseline: return None
    headers = dict(session.headers)
    try:
        r1 = session.request(method, action, data=baseline, headers=headers, timeout=20)
        stripped_payload = build_stripped_payload(baseline)
        stripped_headers = {k:v for k,v in headers.items() if not (k.lower().startswith('x-csrf') or k.lower().startswith('x-xsrf'))}
        r2 = session.request(method, action, data=stripped_payload, headers=stripped_headers, timeout=20)
    except Exception as e:
        return {'type':'active-test-error','page':page_url,'action':action,'detail':str(e)}
    status_similar = (r1.status_code == r2.status_code) or (200 <= r1.status_code < 400 and 200 <= r2.status_code < 400)
    body_similar = simple_response_similarity(r1.text or '', r2.text or '')
    finding = {'page': page_url,'form_action': action,'method': method,'baseline_status': r1.status_code,'stripped_status': r2.status_code,'baseline_body_len': len(r1.text or ''),'stripped_body_len': len(r2.text or '')}
    if status_similar and body_similar:
        finding['type'] = 'active-missing-csrf'
        finding['detail'] = 'Stripped request succeeded similarly -> likely missing CSRF protections.'
        return finding
    else:
        finding['type'] = 'active-protected'
        finding['detail'] = 'CSRF protections likely present.'
        return finding

# --- NEW: XSS Active Test Helpers ---
def test_url_for_xss(session, url):
    """Tests GET parameters in a URL for reflected XSS."""
    findings = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if not query_params:
        return findings

    for param in query_params:
        for payload in XSS_PAYLOADS:
            injected_params = query_params.copy()
            injected_params[param] = [payload]
            new_query = urlencode(injected_params, doseq=True)
            test_url = parsed_url._replace(query=new_query).geturl()
            try:
                r = session.get(test_url, timeout=10)
                if payload in r.text:
                    findings.append({
                        'type': 'reflected-xss-get', 'page': url, 'vulnerable_url': test_url,
                        'parameter': param, 'payload': payload,
                        'detail': 'A payload was reflected unencoded in the response.'
                    })
                    break
            except requests.exceptions.RequestException:
                continue
    return findings

def test_form_for_xss(session, form, page_url):
    """Tests POST form inputs for reflected XSS."""
    findings = []
    action = extract_form_action(form, page_url)
    method = (form.get('method') or 'get').lower()
    if method != 'post':
        return findings

    baseline_data = build_baseline_payload(form)
    for field in baseline_data.keys():
        for payload in XSS_PAYLOADS:
            injected_data = baseline_data.copy()
            injected_data[field] = payload
            try:
                r = session.post(action, data=injected_data, timeout=10)
                if payload in r.text:
                    print(r.text)
                    findings.append({
                        'type': 'reflected-xss-post', 'page': page_url, 'form_action': action,
                        'parameter': field, 'payload': payload,
                        'detail': 'A payload was reflected unencoded in the response.'
                    })
                    break
            except requests.exceptions.RequestException:
                continue
    return findings

# --- Crawler ---
def crawl_and_test(args):
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})
    if args.insecure:
        session.verify = False
    visited = set()
    to_visit = deque([args.base])
    findings = []
    pages_checked = 0
    logged_in = False

    while to_visit and pages_checked < args.max_pages:
        url = normalize_url(to_visit.popleft())
        if url in visited:
            continue
        print(f"[*] Crawling: {url}")
        visited.add(url)

        # NEW: Test GET parameters for XSS on every new URL found
        xss_get_findings = test_url_for_xss(session, url)
        if xss_get_findings:
            findings.extend(xss_get_findings)

        try:
            r = session.get(url, timeout=20)
        except Exception as e:
            findings.append({'type':'fetch-error','url':url,'detail':str(e)})
            continue

        pages_checked += 1
        if 'text/html' not in r.headers.get('Content-Type',''):
            continue
        links, forms = get_links_and_forms(r.text, url)
        if not logged_in:
            for f in forms:
                if looks_like_login_form(f):
                    login_response = attempt_form_login(session, url, args.username, args.password)
                    if login_response:
                        logged_in = True
                        print(f"[+] Logged in successfully. The session is now authenticated.")
                        final_url_after_login = normalize_url(login_response.url)
                        print(f"[+] Redirected to {final_url_after_login}. Adding to crawl queue.")
                        if final_url_after_login not in visited:
                            to_visit.appendleft(final_url_after_login)
                        to_visit.appendleft(url)
                        links, forms = set(), []
                        break
        for link in links:
            if same_domain(link, args.base):
                if args.exclude and any(re.search(p, link) for p in args.exclude): continue
                if link not in visited:
                    to_visit.append(link)
                if looks_like_state_changing_url(link):
                    findings.append({'type':'dangerous-link-get','page':url,'link':link,'detail':'Link contains state-change keyword and uses GET. Potential CSRF.'})
        
        for f in forms:
            # Test for CSRF
            method = (f.get('method') or 'get').lower()
            action = extract_form_action(f, url)
            is_state = method in ('post','put','patch','delete') or looks_like_state_changing_url(action)
            if is_state:
                result = attempt_active_csrf_test(session, f, url)
                if result:
                    findings.append(result)

            # NEW: Test form for POST-based XSS
            xss_post_findings = test_form_for_xss(session, f, url)
            if xss_post_findings:
                findings.extend(xss_post_findings)
            
            time.sleep(args.delay)

    create_report(args.report_file, findings, visited)
    return findings

# --- Reporting ---
def create_report(report_file, findings, visited):
    lines = []
    lines.append("Active Vulnerability Scanner Report (CSRF, XSS)")
    lines.append("Only run on systems you own or are explicitly authorized to test.")
    lines.append(f"\nPages visited ({len(visited)}):")
    for page in sorted(list(visited)):
        lines.append(f"- {page}")
    lines.append(f"\nTotal findings entries: {len(findings)}")
    lines.append("")

    # MODIFIED: Added new XSS finding types to the vulnerable list
    vulnerable_types = ['active-missing-csrf', 'dangerous-link-get', 'reflected-xss-get', 'reflected-xss-post']
    vulnerable_findings = [f for f in findings if f.get('type') in vulnerable_types]
    other_findings = [f for f in findings if f.get('type') not in vulnerable_types]

    if vulnerable_findings:
        lines.append("="*20 + " VULNERABLE FINDINGS " + "="*20)
        for i,f in enumerate(vulnerable_findings, start=1):
            lines.append(f"--- Vulnerability {i} ---")
            lines.append(json.dumps(f, indent=2))
            lines.append("")
    
    if other_findings:
        lines.append("="*20 + " INFORMATIONAL FINDINGS " + "="*20)
        for i,f in enumerate(other_findings, start=1):
            lines.append(f"--- Info {i} ---")
            lines.append(json.dumps(f, indent=2))
            lines.append("")

    with open(report_file, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines))
    print(f"[+] Report written to {report_file}")

# --- CLI ---
def parse_args():
    p = argparse.ArgumentParser(description="Active CSRF and XSS testing crawler with automatic login.")
    p.add_argument('--base', required=True, help='Base URL to start crawl')
    p.add_argument('--username', required=True, help='Username for login')
    p.add_argument('--password', required=True, help='Password for login')
    p.add_argument('--max-pages', type=int, default=500, help='Max pages to visit')
    p.add_argument('--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    p.add_argument('--report-file', default='report.txt', help='Output report filename')
    p.add_argument('--insecure', action='store_true', help='Allow insecure HTTPS (disable cert verify)')
    p.add_argument('--exclude', nargs='*', help='Regex patterns of URLs to exclude from crawling')
    return p.parse_args()

def main():
    args = parse_args()
    print("ACTIVE VULNERABILITY SCANNER — destructive active tests will be performed.")
    print("Ensure you have explicit authorization to test the target system!")
    findings = crawl_and_test(args)
    # MODIFIED: Updated the count to include new XSS findings
    vuln_types = ['active-missing-csrf', 'dangerous-link-get', 'reflected-xss-get', 'reflected-xss-post']
    vuln_count = sum(1 for f in findings if f.get('type') in vuln_types)
    print(f"[+] Crawl finished. Potential vulnerabilities found: {vuln_count}. Report saved to {args.report_file}")

if __name__ == '__main__':
    main()