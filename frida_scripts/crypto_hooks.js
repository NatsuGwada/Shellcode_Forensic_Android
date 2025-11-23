/**
 * AndroSleuth - Custom Crypto Hooks
 * 
 * This script monitors cryptographic operations in Android applications.
 * It hooks into common crypto APIs to detect encryption/decryption attempts.
 * 
 * Usage: Place this file in frida_scripts/ directory
 * AndroSleuth will automatically load it during dynamic analysis.
 */

Java.perform(function() {
    console.log("[*] AndroSleuth - Crypto Hooks Loaded");
    
    // Hook Cipher.getInstance()
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log("\n[CRYPTO] Cipher.getInstance");
            console.log("    Transformation: " + transformation);
            console.log("    Stack trace:");
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            
            return this.getInstance(transformation);
        };
        
        console.log("[+] Hooked: Cipher.getInstance()");
    } catch (e) {
        console.log("[-] Error hooking Cipher: " + e);
    }
    
    // Hook Cipher.init()
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        
        Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
            var mode = ["ENCRYPT_MODE", "DECRYPT_MODE", "WRAP_MODE", "UNWRAP_MODE"][opmode - 1] || "UNKNOWN";
            console.log("\n[CRYPTO] Cipher.init");
            console.log("    Mode: " + mode);
            console.log("    Key Algorithm: " + key.getAlgorithm());
            console.log("    Key Format: " + key.getFormat());
            
            return this.init(opmode, key);
        };
        
        console.log("[+] Hooked: Cipher.init()");
    } catch (e) {
        console.log("[-] Error hooking Cipher.init: " + e);
    }
    
    // Hook Cipher.doFinal()
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        
        Cipher.doFinal.overload('[B').implementation = function(input) {
            console.log("\n[CRYPTO] Cipher.doFinal");
            console.log("    Input length: " + input.length + " bytes");
            
            var result = this.doFinal(input);
            
            console.log("    Output length: " + result.length + " bytes");
            
            return result;
        };
        
        console.log("[+] Hooked: Cipher.doFinal()");
    } catch (e) {
        console.log("[-] Error hooking Cipher.doFinal: " + e);
    }
    
    // Hook MessageDigest (hashing)
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("\n[CRYPTO] MessageDigest.getInstance");
            console.log("    Algorithm: " + algorithm);
            
            return this.getInstance(algorithm);
        };
        
        MessageDigest.digest.overload('[B').implementation = function(input) {
            console.log("\n[CRYPTO] MessageDigest.digest");
            console.log("    Input length: " + input.length + " bytes");
            
            var result = this.digest(input);
            
            console.log("    Hash length: " + result.length + " bytes");
            console.log("    Hash (hex): " + bytesToHex(result));
            
            return result;
        };
        
        console.log("[+] Hooked: MessageDigest");
    } catch (e) {
        console.log("[-] Error hooking MessageDigest: " + e);
    }
    
    // Hook SecretKeySpec (key generation)
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
            console.log("\n[CRYPTO] SecretKeySpec");
            console.log("    Algorithm: " + algorithm);
            console.log("    Key length: " + key.length + " bytes");
            console.log("    Key (hex): " + bytesToHex(key));
            
            return this.$init(key, algorithm);
        };
        
        console.log("[+] Hooked: SecretKeySpec");
    } catch (e) {
        console.log("[-] Error hooking SecretKeySpec: " + e);
    }
    
    // Hook Base64 encoding/decoding
    try {
        var Base64 = Java.use('android.util.Base64');
        
        Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
            console.log("\n[ENCODING] Base64.encodeToString");
            console.log("    Input length: " + input.length + " bytes");
            
            var result = this.encodeToString(input, flags);
            
            console.log("    Output: " + result.substring(0, 50) + (result.length > 50 ? "..." : ""));
            
            return result;
        };
        
        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            console.log("\n[ENCODING] Base64.decode");
            console.log("    Input: " + str.substring(0, 50) + (str.length > 50 ? "..." : ""));
            
            var result = this.decode(str, flags);
            
            console.log("    Output length: " + result.length + " bytes");
            
            return result;
        };
        
        console.log("[+] Hooked: Base64");
    } catch (e) {
        console.log("[-] Error hooking Base64: " + e);
    }
    
    // Helper function to convert bytes to hex
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < Math.min(bytes.length, 16); i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        if (bytes.length > 16) {
            hex += "...";
        }
        return hex;
    }
    
    console.log("[*] Crypto Hooks initialized successfully!");
});
