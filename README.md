# 🛠️ Sunvoy Challenge



## LOOM Video 
[Loom URL](https://www.loom.com/share/7c5bf49382fe4533840450e256fd45b5?sid=244ff536-c11d-4027-8544-2d402554909d)

---

## 🚀 Features

- Logs in using credentials via a web form  
- Manages session cookies across requests  
- Extracts hidden inputs from an HTML page  
- Creates a signed HMAC-SHA1 payload  
- Fetches both user list and current user data  
- Outputs a structured JSON file  

---

## 🧰 Libraries Used

### 1. [`node-fetch`](https://www.npmjs.com/package/node-fetch)
- **Purpose**: Enables `fetch()` in Node.js.
- **Usage**: Makes HTTP requests.
```ts
import fetch from 'node-fetch';
```

---

### 2. [`fetch-cookie`](https://www.npmjs.com/package/fetch-cookie)
- **Purpose**: Adds cookie support to `fetch`.
- **Usage**: Maintains session state.
```ts
import fetchCookie from 'fetch-cookie';
import { CookieJar } from 'tough-cookie';

const fetchWithCookies = fetchCookie(fetch, new CookieJar());
```

---

### 3. [`tough-cookie`](https://www.npmjs.com/package/tough-cookie)
- **Purpose**: Stores/manages cookies.
- **Usage**: Used with `fetch-cookie`.

---

### 4. [`jsdom`](https://www.npmjs.com/package/jsdom)
- **Purpose**: Parses and manipulates HTML.
- **Usage**: Extracts hidden input fields from forms.
```ts
import { JSDOM } from 'jsdom';

const dom = new JSDOM(html);
const inputs = dom.window.document.querySelectorAll('input[type="hidden"]');
```

---

### 5. [Node.js `crypto`](https://nodejs.org/api/crypto.html)
- **Purpose**: Provides cryptographic functions.
- **Usage**: Generates HMAC-SHA1 signature for secure requests.
```ts
import crypto from 'crypto';
```
