# Insecure Deserialization - Complete Learning Path

## 📚 Documentation Overview

This directory contains comprehensive learning materials for insecure deserialization vulnerabilities, covering **all 5 PortSwigger labs** with complete solutions, exploitation code, and detailed analysis of PHP, Java, and Ruby techniques.

---

- Identification techniques
- Lab 1: PHP Object Injection (complete walkthrough)

---
- Java exploitation steps
- Common errors & solutions

---
- PHP vs Java comparison table
- Defense strategies

**Best for**: Learning from mistakes, understanding root causes

**Lab 2 Complete Solution** - Final working payload ready to use
- The error that occurred
**Best for**: Reference when solving Java deserialization challenges

- Gadget chain construction from magic methods
- Serialization and encoding workflow
## 🎯 Learning Path
### Beginner (First time learning)
1. Read [insecure-deserialization.md](insecure-deserialization.md) - conceptual foundation
2. Review [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - identify patterns

1. Read Lab 2 section in [insecure-deserialization.md](insecure-deserialization.md)
2. Use [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for Java checklist
3. If stuck: read [LAB2_FINAL_SOLUTION.md](LAB2_FINAL_SOLUTION.md)
4. Deep dive: [LESSONS_LEARNED.md](LESSONS_LEARNED.md) on Java-specific issues


---


### Lab 1: PHP Object Injection (SOLVED ✓)
- **Vulnerability**: Magic method exploitation via object injection
- **Vulnerability**: CommonsCollections gadget chain during deserialization
- **Method**: ysoserial + InvokerTransformer + URL-encoding critical
- **Target**: Delete file via Runtime.exec()
- **Documentation**: [LAB2_JAVA_GADGET_CHAIN.md](LAB2_JAVA_GADGET_CHAIN.md)

### Lab 3: Symfony PHPGGC Chain (SOLVED ✓)
### Lab 4: Ruby Marshal Deserialization (SOLVED ✓)
- **Vulnerability**: vakzz universal gadget chain for Ruby
- **Method**: Net::WriteAdapter + Gem::RequestSet + Gem::Package classes
- **Key Learning**: Ruby internals, method dispatch, URL-encoding for special chars
- **Documentation**: [LAB4_RUBY_DESERIALIZATION.md](LAB4_RUBY_DESERIALIZATION.md)

- **Key Learning**: Deserialization often triggers OTHER vulnerabilities, not just RCE
- **Documentation**: [LAB5_JAVA_CUSTOM_GADGET.md](LAB5_JAVA_CUSTOM_GADGET.md)
- **Password Extracted**: Via PostgreSQL CAST type error message
---

| **Gadget Source** | Built-in magic | ysoserial | PHPGGC | vakzz chain | Custom app code |
| **Exploitation** | Magic method | GadgetChain | POP chain | Universal chain | SQL injection |
| **RCE Method** | Reflection | InvokerTransformer | Callable chain | Net::WriteAdapter | Error-based SQLi |
| **Difficulty** | ⭐ Low | ⭐⭐⭐ Hard | ⭐⭐ Medium | ⭐⭐⭐⭐ Very Hard | ⭐⭐ Medium |

---

## 🛠️ Exploitation Techniques by Category

### Technique 1: Source Code Discovery
- **Lab 1**: `~` backup files (`CustomTemplate.php~`)
- **Lab 5**: HTML comments (`<!-- <a href=/backup/ProductTemplate.java> -->`)
- **Labs 2,3,4**: Inferred from error messages + library docs

### Technique 2: Gadget Chain Generation
- **Labs 2**: ysoserial tool (pre-built CommonsCollections)
- **Labs 3**: PHPGGC tool (pre-built Symfony)
- **Lab 4**: Manual chain construction (vakzz Net+Gem classes)
- **Lab 5**: Custom application class (not a traditional gadget)

### Technique 3: Encoding & Injection
- **Lab 1**: Base64 (simple)
- **Lab 2**: Base64 → URL-encode (critical!)
- **Lab 3**: Base64 → HMAC signature addition
- **Lab 4**: Ruby Marshal → URL-encode (special chars)
- **Lab 5**: Base64 (standard)
- **Lab 5**: Cookie-based deserialization (+ SQL execution)


## ✅ Labs Covered

### 1. [insecure-deserialization.md](insecure-deserialization.md)
- Fundamental concepts and vulnerability patterns
- Identification techniques and testing methodology
- Lab-by-lab walkthroughs and comparisons
- Comprehensive lessons learned across all 5 labs
- Language-specific exploitation patterns (PHP, Java, Ruby)

**Best for**: Understanding concepts from first principles

---

### 2. [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
**Cheat Sheet** - Quick lookup during exploitation
- Identification checklist
- Language-specific exploitation steps
- Template payloads for each language
- Verification steps
- Essential tools list

**Best for**: During active exploitation, quick lookups

---

# XSS (Cross Site Scripting)



---

### 3. [LESSONS_LEARNED.md](LESSONS_LEARNED.md)
**In-Depth Analysis** - Understand what went wrong and why
- Three-layer encoding problem explained
- Module access flag issue (Java 16+)
- Debugging checklist (5 categories)
- PHP vs Java vs Ruby comparison tables
- Security implications
- Defense strategies

**Best for**: Learning from mistakes, understanding root causes

---

### 4. [MASTER_WALKTHROUGH.md](MASTER_WALKTHROUGH.md)
**Complete Solution Guide** - All 5 labs in one file
- Step-by-step solutions for each lab
- Working payloads and encoding
- Common pitfalls and solutions
- Tool usage and command references

**Best for**: Reference during lab solving

---

### 5. Individual Lab Documentation
- [LAB5_JAVA_CUSTOM_GADGET.md](LAB5_JAVA_CUSTOM_GADGET.md) - Custom gadget chain + SQL injection
- [LAB4_RUBY_DESERIALIZATION.md](LAB4_RUBY_DESERIALIZATION.md) - vakzz universal gadget for Ruby
- [LAB3_SYMFONY_GADGET_CHAIN.md](LAB3_SYMFONY_GADGET_CHAIN.md) - Symfony PHPGGC exploitation  
- [LAB2_JAVA_GADGET_CHAIN.md](LAB2_JAVA_GADGET_CHAIN.md) - Apache Commons via ysoserial
- [LAB1_PHP_OBJECT_INJECTION.md](LAB1_PHP_OBJECT_INJECTION.md) - PHP Reflection RCE

**Best for**: Deep dive into specific lab techniques

---

## 🔑 Critical Success Factors

### What Made Each Lab Work

**Lab 1 (PHP)**  
✅ Found source code using `~` backup file technique  
✅ Identified `__destruct()` magic method  
✅ Used PHP Reflection for private property access  
✅ Proper serialization of exploit object  

**Lab 2 (Java)**  
✅ **URL-encoded the entire base64 payload** (this was critical!)  
✅ Placed `--add-opens` flags in correct position (before -jar)  
✅ Used Burp Suite for reliable cookie injection  
✅ Read error messages to identify gadget chain issues  

**Lab 3 (PHP Symfony)**  
✅ Generated correct HMAC-SHA1 signature using raw message  
✅ Used PHPGGC for consistent gadget chain  
✅ Proper JSON structure for serialized object  
✅ Understood message format requirements  

**Lab 4 (Ruby)**  
✅ Researched vakzz universal gadget chain from devcraft.io  
✅ Used Ruby Marshal binary format  
✅ URL-encoded special characters in gadget chain  
✅ Properly formed Net::WriteAdapter + Gem classes  

**Lab 5 (Java Custom)**  
✅ Found source code via HTML comment leak  
✅ Identified SQL injection in custom readObject()  
✅ Used PostgreSQL CAST() for error-based data extraction  
✅ Understood that deserialization was the TRIGGER, not the exploit

---

## 🛠️ Tools Used

- **Burp Suite** - Cookie injection and request inspection
- **ysoserial** - Java gadget chain generation
- **PHP CLI** - Local testing of serialization
- **Python 3** - URL-encoding
- **curl/wget** - HTTP requests
- **xxd** - Binary inspection

---

## 📊 Key Statistics

| Metric | Value |
|--------|-------|
| **Labs Completed** | 5/5 (100%) ✅ |
| **PHP-based Labs** | 2 (Labs 1, 3) |
| **Java-based Labs** | 2 (Labs 2, 5) |
| **Ruby-based Labs** | 1 (Lab 4) |
| **Critical Challenges Found** | 5+ (encoding, HMAC, gadget discovery, SQL injection) |
| **Gadget Chains Tested** | 7+ (CommonsCollections variants, vakzz, PHPGGC, custom) |
| **Total Documentation Pages** | 12+ |
| **Key Learnings Identified** | 20+ |

---

## 🎓 What You've Learned

### Technical Skills
- [x] Identify serialization formats (PHP, Java, Ruby)
- [x] Decode and analyze serialized objects
- [x] Find and exploit magic methods (`__destruct`, `__wakeup`)
- [x] Understand custom readObject() deserialization hooks
- [x] Generate gadget chain payloads (ysoserial, PHPGGC, manual)
- [x] Properly encode payloads for different transports
- [x] Exploit SQL injection via deserialization triggers
- [x] Use Burp Suite for exploitation
- [x] Debug exploitation failures systematically
- [x] Try alternative approaches and gadget chains

### Security Concepts
- [x] Why serialization of untrusted data is dangerous
- [x] How gadget chains enable RCE
- [x] Importance of input validation and integrity checks
- [x] Defense mechanisms (HMAC, digital signatures, allow-lists)
- [x] Real-world vulnerability patterns and impacts
- [x] OWASP classifications and CVE patterns
- [x] Language-specific vulnerabilities (PHP magic, Java gadgets, Ruby dispatch)
- [x] Deserialization as trigger vs. exploit distinction

### Problem-Solving
- [x] Systematic debugging and error analysis
- [x] Error message interpretation and data extraction
- [x] Trial-and-error methodology for unknown challenges
- [x] Tool usage, combination, and adaptation
- [x] Documentation creation for future reference
- [x] Research techniques (GitHub, security blogs, GitHub issues)

---

## 🚀 Next Steps

### Consolidate Knowledge
- [ ] Solve similar labs on PortSwigger (if available)
- [ ] Try deserialization in different languages (Python pickle, .NET)
- [ ] Attempt real-world scenarios with partial source code
- [ ] Create custom exploits for additional gadget chains

### Deepen Understanding
- [ ] Study more gadget chains in ysoserial source
- [ ] Understand XALAN bytecode generation
- [ ] Learn InvokerTransformer internals
- [ ] Research Apache Commons Collections versions and differences
- [ ] Analyze Ruby reflection and method dispatch
- [ ] Study PostgreSQL error messages and type casting

### Apply Skills
- [ ] Participate in bug bounty programs
- [ ] Audit real applications for deserialization vulnerabilities
- [ ] Create custom gadget chains for specific libraries
- [ ] Develop defenses against these attacks
- [ ] Contribute to open-source security tools

---

## 📝 Notes for Review

**Remember this chain of reasoning:**

```
Serialized data in cookie (no HMAC)
  ↓
User can modify cookie freely
  ↓
Server deserializes without validation
  ↓
Magic method / Gadget chain / Custom code executes
  ↓
Arbitrary code execution OR data extraction
  ↓
Complete system compromise
```

**The fix is simple but often missed:**
```
NEVER deserialize untrusted data
OR
- Use allow-lists (if deserialization required)
- Sign with HMAC or digital signature
- Use JSON instead of binary serialization
- Validate strictly and limit scope
- Keep libraries updated
- Disable unnecessary components
```

---

## 📚 References & Further Reading

- [OWASP Deserialization](https://owasp.org/www-community/Deserialization_of_untrusted_data)
- [ysoserial GitHub](https://github.com/frohoff/ysoserial)
- [PHPGGC GitHub](https://github.com/ambionics/phpggc)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Apache Commons Collections](https://commons.apache.org/proper/commons-collections/)
- [Ruby Marshal Format](https://docs.ruby-lang.org/en/3.0.0/marshal_rdoc.html)

---

## 🏆 Milestones Achieved

| Milestone | Status | Evidence |
|-----------|--------|----------|
| **Lab 1 Solved** | ✅ Complete | File deleted via PHP magic method |
| **Lab 2 Solved** | ✅ Complete | File deleted via CommonsCollections gadget |
| **Lab 3 Solved** | ✅ Complete | File deleted via PHPGGC Symfony chain |
| **Lab 4 Solved** | ✅ Complete | File deleted via vakzz Ruby gadget |
| **Lab 5 Solved** | ✅ Complete | Admin password extracted + user deleted |
| **All Labs Documented** | ✅ Complete | 12+ detailed documentation files |
| **Cross-Language Expertise** | ✅ Complete | PHP, Java, Ruby exploitation mastered |
| **Custom Gadget Creation** | ✅ Complete | Manual chain creation for unknown libraries |

---

**Last Updated**: 2025  
**Status**: All 5 PortSwigger Insecure Deserialization Labs SOLVED ✅  
**Documentation**: Complete and comprehensive 📚  
**Ready for**: Teaching, reference, and real-world application 🎯
