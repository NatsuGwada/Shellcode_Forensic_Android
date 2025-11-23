/**
 * AndroSleuth - Network Monitoring Hooks
 * 
 * This script monitors network connections and HTTP requests.
 * It intercepts common networking APIs to detect data exfiltration.
 * 
 * Usage: Place this file in frida_scripts/ directory
 */

Java.perform(function() {
    console.log("[*] AndroSleuth - Network Hooks Loaded");
    
    // Hook URL constructor
    try {
        var URL = Java.use('java.net.URL');
        
        URL.$init.overload('java.lang.String').implementation = function(url) {
            console.log("\n[NETWORK] URL created");
            console.log("    URL: " + url);
            
            // Detect suspicious domains
            if (url.includes("pastebin") || url.includes("hastebin") || 
                url.includes(".ru") || url.includes(".cn")) {
                console.log("    ⚠️  SUSPICIOUS DOMAIN DETECTED!");
            }
            
            return this.$init(url);
        };
        
        console.log("[+] Hooked: URL constructor");
    } catch (e) {
        console.log("[-] Error hooking URL: " + e);
    }
    
    // Hook HttpURLConnection
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        HttpURLConnection.connect.implementation = function() {
            console.log("\n[NETWORK] HttpURLConnection.connect");
            console.log("    URL: " + this.getURL().toString());
            console.log("    Method: " + this.getRequestMethod());
            
            return this.connect();
        };
        
        console.log("[+] Hooked: HttpURLConnection.connect()");
    } catch (e) {
        console.log("[-] Error hooking HttpURLConnection: " + e);
    }
    
    // Hook OkHttp (modern networking)
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        
        OkHttpClient.newCall.implementation = function(request) {
            console.log("\n[NETWORK] OkHttp Request");
            console.log("    URL: " + request.url().toString());
            console.log("    Method: " + request.method());
            
            var headers = request.headers();
            console.log("    Headers:");
            for (var i = 0; i < headers.size(); i++) {
                console.log("        " + headers.name(i) + ": " + headers.value(i));
            }
            
            return this.newCall(request);
        };
        
        console.log("[+] Hooked: OkHttpClient.newCall()");
    } catch (e) {
        console.log("[-] OkHttp not found or error: " + e);
    }
    
    // Hook Socket connections
    try {
        var Socket = Java.use('java.net.Socket');
        
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            console.log("\n[NETWORK] Socket connection");
            console.log("    Host: " + host);
            console.log("    Port: " + port);
            
            // Detect suspicious ports
            if ([4444, 5555, 6666, 1337, 31337].includes(port)) {
                console.log("    ⚠️  SUSPICIOUS PORT DETECTED!");
            }
            
            return this.$init(host, port);
        };
        
        console.log("[+] Hooked: Socket constructor");
    } catch (e) {
        console.log("[-] Error hooking Socket: " + e);
    }
    
    // Hook WebView URL loading
    try {
        var WebView = Java.use('android.webkit.WebView');
        
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("\n[WEBVIEW] Loading URL");
            console.log("    URL: " + url);
            
            // Detect data URIs (can be used for data exfiltration)
            if (url.startsWith("data:")) {
                console.log("    ⚠️  DATA URI DETECTED!");
                console.log("    Content preview: " + url.substring(0, 100) + "...");
            }
            
            return this.loadUrl(url);
        };
        
        console.log("[+] Hooked: WebView.loadUrl()");
    } catch (e) {
        console.log("[-] Error hooking WebView: " + e);
    }
    
    // Hook DNS resolution
    try {
        var InetAddress = Java.use('java.net.InetAddress');
        
        InetAddress.getByName.implementation = function(host) {
            console.log("\n[DNS] Resolution attempt");
            console.log("    Hostname: " + host);
            
            var result = this.getByName(host);
            
            console.log("    Resolved to: " + result.getHostAddress());
            
            return result;
        };
        
        console.log("[+] Hooked: InetAddress.getByName()");
    } catch (e) {
        console.log("[-] Error hooking InetAddress: " + e);
    }
    
    console.log("[*] Network Hooks initialized successfully!");
});
