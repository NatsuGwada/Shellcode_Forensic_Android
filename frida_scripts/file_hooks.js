/**
 * AndroSleuth - File System Monitoring Hooks
 * 
 * This script monitors file system operations.
 * It tracks file reads/writes to detect data theft or malicious file operations.
 * 
 * Usage: Place this file in frida_scripts/ directory
 */

Java.perform(function() {
    console.log("[*] AndroSleuth - File System Hooks Loaded");
    
    // Hook FileOutputStream (writing files)
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        
        FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function(path, append) {
            console.log("\n[FILE] FileOutputStream opened");
            console.log("    Path: " + path);
            console.log("    Mode: " + (append ? "APPEND" : "WRITE"));
            
            // Detect suspicious paths
            if (path.includes("/sdcard/") || path.includes("/data/data/")) {
                console.log("    ⚠️  Writing to sensitive location!");
            }
            
            return this.$init(path, append);
        };
        
        console.log("[+] Hooked: FileOutputStream constructor");
    } catch (e) {
        console.log("[-] Error hooking FileOutputStream: " + e);
    }
    
    // Hook FileInputStream (reading files)
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        
        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            console.log("\n[FILE] FileInputStream opened");
            console.log("    Path: " + path);
            
            // Detect sensitive file access
            if (path.includes("contacts") || path.includes("sms") || 
                path.includes("accounts") || path.includes(".db")) {
                console.log("    ⚠️  Reading sensitive file!");
            }
            
            return this.$init(path);
        };
        
        console.log("[+] Hooked: FileInputStream constructor");
    } catch (e) {
        console.log("[-] Error hooking FileInputStream: " + e);
    }
    
    // Hook File operations
    try {
        var File = Java.use('java.io.File');
        
        File.delete.implementation = function() {
            console.log("\n[FILE] File deletion");
            console.log("    Path: " + this.getAbsolutePath());
            
            var result = this.delete();
            
            console.log("    Success: " + result);
            
            return result;
        };
        
        console.log("[+] Hooked: File.delete()");
    } catch (e) {
        console.log("[-] Error hooking File: " + e);
    }
    
    // Hook SharedPreferences (app settings/data)
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        var Editor = Java.use('android.content.SharedPreferences$Editor');
        
        Editor.putString.implementation = function(key, value) {
            console.log("\n[PREFS] SharedPreferences.putString");
            console.log("    Key: " + key);
            console.log("    Value: " + value.substring(0, 50) + (value.length > 50 ? "..." : ""));
            
            // Detect sensitive data storage
            if (key.toLowerCase().includes("password") || 
                key.toLowerCase().includes("token") ||
                key.toLowerCase().includes("secret") ||
                key.toLowerCase().includes("key")) {
                console.log("    ⚠️  STORING SENSITIVE DATA!");
            }
            
            return this.putString(key, value);
        };
        
        console.log("[+] Hooked: SharedPreferences.Editor.putString()");
    } catch (e) {
        console.log("[-] Error hooking SharedPreferences: " + e);
    }
    
    // Hook SQLite database operations
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
            console.log("\n[SQL] Executing query");
            console.log("    SQL: " + sql);
            
            // Detect suspicious queries
            if (sql.toLowerCase().includes("drop") || 
                sql.toLowerCase().includes("delete") ||
                sql.toLowerCase().includes("truncate")) {
                console.log("    ⚠️  DESTRUCTIVE SQL OPERATION!");
            }
            
            return this.execSQL(sql);
        };
        
        console.log("[+] Hooked: SQLiteDatabase.execSQL()");
    } catch (e) {
        console.log("[-] Error hooking SQLiteDatabase: " + e);
    }
    
    // Hook ContentProvider access
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 
            'java.lang.String', '[Ljava.lang.String;', 'java.lang.String')
            .implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            
            console.log("\n[CONTENT] ContentProvider query");
            console.log("    URI: " + uri.toString());
            
            // Detect access to sensitive providers
            var uriStr = uri.toString();
            if (uriStr.includes("contacts") || uriStr.includes("sms") || 
                uriStr.includes("call_log") || uriStr.includes("calendar")) {
                console.log("    ⚠️  ACCESSING SENSITIVE CONTENT PROVIDER!");
            }
            
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
        
        console.log("[+] Hooked: ContentResolver.query()");
    } catch (e) {
        console.log("[-] Error hooking ContentResolver: " + e);
    }
    
    console.log("[*] File System Hooks initialized successfully!");
});
