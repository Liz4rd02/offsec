import requests

# =============================================================================
# GET REQUEST
# =============================================================================

response = requests.get(
    "https://httpbin.org/get",
    params={                     # Query string parameters
        "user": "alice",
        "page": 1,
    },
    headers={                    # Optional headers
        "User-Agent": "MyScript/1.0",
    },
    cookies={                    # Optional cookies
        "session": "abc123",
    },
    timeout=5,                   # Optional timeout
)

# Response information
print(response.status_code)      # 200
print(response.headers)          # Response headers
print(response.url)              # Final URL
print(response.text)             # Body as string
print(response.content)          # Body as bytes
print(response.json())           # Parse JSON

response.raise_for_status()      # Raise exception on 4xx/5xx


# =============================================================================
# POST REQUEST
# =============================================================================

# Pick ONE payload style depending on what the server expects.

response = requests.post(
    "https://httpbin.org/post",

    # Query parameters (optional)
    params={"debug": "true"},

    # JSON body (most common for APIs)
    json={
        "username": "alice",
        "password": "secret",
    },

    # Form body (application/x-www-form-urlencoded)
    # data={
    #     "username": "alice",
    #     "password": "secret",
    # },

    # Raw body
    # data=b"raw bytes",

    headers={
        "Authorization": "Bearer TOKEN",
    },

    timeout=5,
)

print(response.status_code)
print(response.text)
print(response.json())


# =============================================================================
# FILE UPLOAD (multipart/form-data)
# =============================================================================

with open("file.txt", "rb") as f:
    response = requests.post(
        "https://httpbin.org/post",
        files={
            "file": f
        }
    )

print(response.json())


# =============================================================================
# SESSION (reuses connections + preserves cookies)
# =============================================================================

session = requests.Session()

session.headers.update({
    "Authorization": "Bearer TOKEN"
})

# Requests now share:
# - TCP connections
# - cookies
# - default headers

r1 = session.get("https://httpbin.org/get")
r2 = session.post(
    "https://httpbin.org/post",
    json={"message": "hello"}
)

session.close()
