#!/usr/bin/env python3
"""Parse a user's 'Copy as cURL' paste -> extract Cookie header + URL.
Usage: python parse_curl_cookies.py "<paste entire curl command>" [--url-filter domain]
Outputs: the cookie header (for curl -H replay) and the target URL."""
import sys, re

def main():
    if len(sys.argv) < 2:
        print(__doc__); return 1
    paste = sys.argv[1]
    url_filter = None
    if '--url-filter' in sys.argv:
        url_filter = sys.argv[sys.argv.index('--url-filter') + 1]

    # URL
    m = re.search(r'--url\s+\^?"?(https?://[^"\s^]+)', paste) or \
        re.search(r'curl\s+-?\w*\s*[\s"\'^]*"(https?://[^"\s^]+)', paste) or \
        re.search(r'(https?://[^\s"\'^]+)', paste)
    url = m.group(1).rstrip('^"') if m else None

    # Cookie header: -b "..." or -H "cookie: ..." (Windows caret-escaped quotes)
    # strict match first: stop at the closing quote (cookie values don't contain quotes)
    cookies = None
    m = re.search(r'-b\s+\^?"([^"^]*)"', paste)
    if m and m.group(1).strip(): cookies = m.group(1)
    if not cookies:
        m = re.search(r'-H\s+\^?"[Cc]ookie:\s*([^"^]*)"', paste)
        if m and m.group(1).strip(): cookies = m.group(1)
    if not cookies:
        # fallback: multiline pastes where the value runs to end-of-line
        m = re.search(r'-b\s+\^?"(.*?)"\s*(?:\n|\^|$)', paste, re.S)
        if m: cookies = m.group(1)
        if not cookies:
            m = re.search(r'-H\s+\^?"[Cc]ookie:\s*(.*?)"\s*(?:\n|\^|$)', paste, re.S)
            if m: cookies = m.group(1)
    # strip caret escapes and dollar-escapes Edge adds
    if cookies:
        cookies = cookies.replace('^', '').replace('^$^', '$').replace('""', '"')

    print("URL:", url)
    if url_filter and url and url_filter not in url:
        print(f"NOTE: url does not contain filter '{url_filter}'")
    if cookies:
        # list individual cookies
        pairs = [c.strip() for c in cookies.split(';') if '=' in c]
        print(f"cookies: {len(pairs)}")
        for c in pairs:
            k = c.split('=')[0]
            print(f"  {k} = {c[len(k)+1:][:40]}{'...' if len(c)-len(k)-1 > 40 else ''}")
        print("\nCOOKIE HEADER (curl -H replay):")
        print(f'curl -s "{url or "<URL>"}" -H "Cookie: {cookies}"')
        # save for direct use
        open('session_cookie_header.txt', 'w').write(f'Cookie: {cookies}\n')
        print("\nsaved -> session_cookie_header.txt")
    else:
        print("no cookie header found in paste")
    return 0

if __name__ == '__main__':
    sys.exit(main())
