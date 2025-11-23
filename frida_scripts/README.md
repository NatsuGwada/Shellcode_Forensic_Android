# Frida Scripts for AndroSleuth

This directory contains Frida JavaScript hooks for dynamic analysis of Android applications.

## 📱 Prerequisites

### On Your Computer
```bash
pip install frida frida-tools
```

### On Android Device
1. Download frida-server for your device architecture from:
   https://github.com/frida/frida/releases

2. Push to device and run:
```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

## 🎯 Built-in Hooks

The default hook script monitors:

### Crypto Operations
- `Cipher.getInstance()` - Encryption/decryption initialization
- `Cipher.doFinal()` - Encryption/decryption execution
- `MessageDigest.getInstance()` - Hashing operations

### Network Activity
- `HttpURLConnection` - HTTP requests
- `OkHttp` - Modern HTTP client
- Captures URLs, methods, headers

### File Operations
- `FileOutputStream` - File writes
- `FileInputStream` - File reads
- Tracks paths and modes

### Dangerous APIs
- `Runtime.exec()` - Command execution ⚠️
- `SmsManager.sendTextMessage()` - SMS sending ⚠️
- `DexClassLoader` - Dynamic code loading ⚠️

### Privacy APIs
- `LocationManager.getLastKnownLocation()` - Location access
- Contact/SMS database access

### Security
- SSL Certificate Pinning detection
- Root detection attempts

## 🔧 Usage

### Automatic (via AndroSleuth)
```bash
# Attach to running app
python src/androsleuth.py -a app.apk --frida --device <device_id>

# Monitor for 60 seconds
python src/androsleuth.py -a app.apk --frida --duration 60
```

### Manual (Frida CLI)
```bash
# List processes
frida-ps -U

# Attach to app
frida -U -n com.example.app -l hooks.js

# Spawn app with hooks
frida -U -f com.example.app -l hooks.js --no-pause
```

## 📝 Custom Hooks

Create `hooks.js` in this directory to override default hooks:

```javascript
// Custom hook example
Java.perform(function() {
    console.log("[*] Loading custom hooks...");
    
    // Hook specific class
    var MyClass = Java.use("com.example.app.MyClass");
    MyClass.sensitiveMethod.implementation = function(arg) {
        console.log("[+] sensitiveMethod called with: " + arg);
        send({
            type: 'custom',
            method: 'sensitiveMethod',
            argument: arg,
            timestamp: Date.now()
        });
        return this.sensitiveMethod(arg);
    };
});
```

## 🎓 Hook Patterns

### Method Overloading
```javascript
MyClass.method.overload('java.lang.String').implementation = function(str) {
    // Your code
    return this.method(str);
};
```

### Constructor Hooking
```javascript
MyClass.$init.implementation = function() {
    console.log("[+] Constructor called");
    return this.$init();
};
```

### Return Value Modification
```javascript
MyClass.isRooted.implementation = function() {
    console.log("[+] Root check bypassed");
    return false;  // Always return false
};
```

### Native Function Hooking
```javascript
Interceptor.attach(Module.findExportByName("libnative.so", "native_function"), {
    onEnter: function(args) {
        console.log("[+] native_function called");
        console.log("    arg0: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("[+] Return value: " + retval);
    }
});
```

## 📊 Output Format

Messages sent via `send()` are structured:

```json
{
    "type": "network|file|crypto|exec|sms|custom",
    "api": "API name",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "timestamp": 1234567890,
    "...": "additional fields"
}
```

## ⚠️ Troubleshooting

### "Failed to spawn: unable to find process with name"
- App not installed or wrong package name
- Check with: `adb shell pm list packages | grep <name>`

### "Failed to attach: process not found"
- App not running, use spawn mode
- Or start app manually first

### "Unable to connect to remote frida-server"
- frida-server not running on device
- Version mismatch between frida and frida-server
- Check with: `frida-ps -U`

### "Script error: Java.available is false"
- App not fully initialized yet
- Add delay: `setTimeout(function() { Java.perform(...) }, 1000);`

## 🔗 Resources

- [Frida Documentation](https://frida.re/docs/home/)
- [Frida CodeShare](https://codeshare.frida.re/)
- [Android Hooking Examples](https://github.com/OWASP/owasp-mastg)
- [Frida Handbook](https://learnfrida.info/)

## 🛡️ Best Practices

1. **Test on non-production devices** - Frida requires root/jailbreak
2. **Monitor resource usage** - Hooks can impact performance
3. **Filter sensitive data** - Don't log passwords/tokens
4. **Handle errors gracefully** - Use try-catch blocks
5. **Clean up** - Detach properly when done

## 📄 Legal Notice

These scripts are for **security research and testing purposes only**. Use only on applications you own or have permission to test.
