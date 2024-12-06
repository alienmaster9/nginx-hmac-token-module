# nginx-hmac-token-module
hmac token module for nginx protects any directive

Compilation Instructions:
1. Save this file as ngx_http_hmac_module.c
2. Use the following commands to compile and include the module in NGINX:

   $ ./configure --add-module=/path/to/ngx_http_hmac_module.c
   $ make
   $ make install

Client Code Example:
- Generate HMAC token using Python:

```python
import hmac
import hashlib
import base64
import time

def generate_hmac_token(secret, acl, exp, ip=None):
    message = acl + str(exp)
    if ip:
        message += ip
    
    digest = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()

secret = "your_secret_key"
acl = "/path/to/resource"
exp = int(time.time()) + 3600  # 1 hour from now
ip = "192.168.1.1"

token = generate_hmac_token(secret, acl, exp, ip)
print(f"Generated HMAC Token: {token}")
```

NGINX Configuration Example:

```nginx
http {
    server {
        listen 80;
        server_name localhost;

        location /protected {
            hmac_protection;
            proxy_pass http://backend;
        }
    }
}
```
