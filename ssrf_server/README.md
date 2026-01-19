! You can use it only in educational purposes !

# SSRF Server
1) To run server:
```cmd
(optional) .venv\Scripts\activate
pip install -r requirements.txt
python server.py
python target_server.py
```

2) Run Burp Suite or similar software
3) Open http://127.0.0.1:8000 or http://localhost:8000 in Burp Browser
4) Browser: Enter any valid URL in Fetch Box (e.g. https://soundcloud.com/keinemusik)
5) Burp: Proxy -> HTTP History -> Find latest POST request (/fetch) from 127.0.0.1:8000 and add this request to Repeater (ctrl + R)
6) Burp Repeater: Change url in Request body from https://soundcloud.com/keinemusik to http://127.0.0.1:8000
7) Burp Repeater: Select 8000 with LMB and send it to Inrtuder (ctrl + I)
8) Burp Intruder: Select Payload type -> Numbers -> Number range from 8990 to 9010 (to find it faster) -> Start attack
9) Burp Intruder: Find port 9000 with status 200 OK. 
10) Return to Repeater and replace URL with http://127.0.0.1:9000
11) Find secret info at http://127.0.0.1:9000/secret
