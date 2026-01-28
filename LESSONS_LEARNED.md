# Insecure Deserialization - Complete Learning Summary

## ✅ Labs Completed

### Lab 1: PHP Object Injection ✓ SOLVED
- **Target**: Delete `/home/carlos/morale.txt` via `__destruct()` magic method
- **Key**: Private property access using PHP Reflection
- **Result**: Successful RCE through object injection

### Lab 2: Java Gadget Chain ✓ SOLVED  
- **Target**: Delete `/home/carlos/morale.txt` via gadget chain RCE
- **Key**: Proper URL-encoding + correct `--add-opens` flags for Java 16+
- **Result**: Successful RCE through CommonsCollections4 gadget chain

---

## 🎓 Critical Lessons

### The Three-Layer Encoding Problem (Lab 2)

```
Original Command: rm /home/carlos/morale.txt
↓
Embedded in gadget chain bytecode
↓
ysoserial generates binary serialized object
↓
Base64 encode the binary
↓
URL-ENCODE THE BASE64 (this was the missing step!)
↓
Inject into cookie
↓
Server deserializes → executes command
```

**Why URL-encoding matters:**
- Base64 alphabet includes `+`, `/`, `=`
- HTTP/cookies automatically interpret these as URL characters
- Without explicit URL-encoding, server reads corrupted data
- Result: Either 500 error or deserialization failure

### The Module Access Flag Problem (Java 16+)

**Wrong order:**
```bash
java --add-opens... -jar ysoserial-all.jar CommonsCollections4...
```

**Correct order:**
```bash
java \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens java.base/java.net=ALL-UNNAMED \
  --add-opens java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'COMMAND' | base64 | python3 -c "..."
```

**Why it matters:**
- Flags affect how JVM generates the gadget chain bytecode
- Without them, certain class constructors aren't accessible
- Results in: `InstantiateTransformer: Constructor threw an exception`

---

## 🔍 Debugging Checklist

When exploitation fails, check in this order:

### 1. Encoding Issues
- [ ] Is output base64-encoded?
- [ ] If for cookie: is it URL-encoded after base64?
- [ ] Any special characters like `+`, `/`, `=`?
- [ ] Try: `base64 -d` to verify, then `python3 -c "import urllib.parse; print(urllib.parse.quote(...))"` to verify

### 2. Gadget Chain Compatibility  
- [ ] Is Java 16+? Need `--add-opens` flags
- [ ] Are they in the right place? (before `-jar`, not before `java`)
- [ ] Is the Apache Commons library on target server?
- [ ] Try different gadget chains: CC4, CC5, CC6, CC3, CC1

### 3. Payload Validation
- [ ] Is the command properly quoted?
- [ ] Does command work in shell directly?
- [ ] Is target file/directory writable?
- [ ] Any output redirects needed? (`> /dev/null 2>&1`)

### 4. Injection Method
- [ ] Use Burp Suite, not browser DevTools (more reliable)
- [ ] In Burp Repeater: edit Cookie header directly
- [ ] Verify entire payload is pasted, no truncation
- [ ] Send request and check response for errors

### 5. Verification
- [ ] Check Burp response for specific error messages
- [ ] Try multiple times (deserialization might happen on 2nd request)
- [ ] Navigate to different pages and back
- [ ] Check if exploit actually executed (refresh page, check status)

---

## 📊 Comparison: PHP vs Java

### Detection

**PHP:**
- Session cookie shows: `O:4:"User":2:{...}`
- Human-readable format
- Can manually decode easily
- Small payload size

**Java:**
- Session cookie shows: `rO0AB...` (binary Base64)
- Larger payload
- Less human-readable
- Requires tools to generate

### Exploitation

**PHP:**
```php
class CustomTemplate {
    private $lock_file_path;
}
$obj = new CustomTemplate();
// Use reflection to set private property
// Serialize and base64 encode
```

**Java:**
```bash
ysoserial -jar CommonsCollections4 'command' | base64 | url-encode
```

### Triggers

**PHP:**
- Magic method `__destruct()` runs on object destruction
- Called automatically at end of request
- Synchronous execution

**Java:**
- Gadget chain runs during `ObjectInputStream.readObject()`
- Deserialization → chain triggers → RCE
- Multiple constructor calls in sequence

---

## 🛡️ Security Implications

### Why These Matter

1. **No Signature/Integrity Check**
   - Cookies not HMAC signed
   - Attacker freely modifies serialized data
   - Server blindly deserializes

2. **Dangerous Defaults**
   - Serialization meant for internal use only
   - Should never trust user-supplied serialized data
   - But commonly used in sessions

3. **Gadget Chains**
   - Java's rich class libraries provide "gadgets"
   - ysoserial finds chains in common libraries
   - Makes exploitation almost trivial once library is present

### Defense Strategies

**For Developers:**
```
1. NEVER deserialize untrusted data
2. If must deserialize:
   - Use allow-lists of safe classes
   - Sign with HMAC/cryptographic signature
   - Use safer formats (JSON, Protocol Buffers, MessagePack)
   - Validate thoroughly before deserialization
3. Keep dependencies updated
   - Especially Apache Commons
4. Monitor for dangerous pattern deserialization
```

**For Security Teams:**
```
1. Audit all serialization usage
2. Identify session storage mechanisms
3. Look for: cookies with Base64 content, Java/PHP serialization
4. Test with malicious payloads
5. Enforce secure coding standards
```

---

## 💡 Key Takeaways

1. **Encoding Matters**
   - Always URL-encode data in cookies
   - Verify encoding at each step
   - Double-check special characters

2. **Error Messages Tell Stories**
   - 500 error ≠ failure
   - Read the exception type
   - Java module errors = JVM protections, need flags

3. **Tool Placement**
   - `--add-opens` in ysoserial command, not before `java`
   - Order of arguments matters
   - Read tool documentation carefully

4. **Testing Framework**
   - Burp Suite > Browser DevTools for cookie injection
   - Manual URL-encoding > relying on browser
   - Check actual bytes sent, not what you typed

5. **Fundamentals Over Shortcuts**
   - Understand the attack chain
   - Know why each step matters
   - Don't just copy-paste commands blindly

---

## 📖 References for Further Study

- **ysoserial**: https://github.com/frohoff/ysoserial
- **OWASP Deserialization**: https://owasp.org/www-community/Deserialization_of_untrusted_data
- **PortSwigger**: https://portswigger.net/web-security/deserialization
- **Apache Commons Collections**: https://commons.apache.org/proper/commons-collections/
