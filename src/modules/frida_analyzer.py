#!/usr/bin/env python3
"""
Frida Instrumentation Module
Dynamic analysis using Frida for runtime behavior monitoring
"""

import os
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

# Try to import frida
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from ..utils.logger import setup_logger

logger = setup_logger('frida_analyzer')


class FridaAnalyzer:
    """Dynamic analysis using Frida instrumentation"""
    
    def __init__(self, package_name: str, device_id: Optional[str] = None):
        """
        Initialize Frida analyzer
        
        Args:
            package_name: Android package name to instrument
            device_id: Device ID (None for USB device)
        """
        self.package_name = package_name
        self.device_id = device_id
        self.device = None
        self.session = None
        self.script = None
        
        self.results = {
            'frida_available': FRIDA_AVAILABLE,
            'device_connected': False,
            'app_running': False,
            'hooks_installed': False,
            'api_calls': [],
            'network_requests': [],
            'file_operations': [],
            'crypto_operations': [],
            'suspicious_behavior': [],
            'threat_score': 0
        }
        
        if not FRIDA_AVAILABLE:
            logger.warning("Frida not available. Install with: pip install frida frida-tools")
            return
        
        # Script directory
        project_root = Path(__file__).parent.parent.parent
        self.scripts_dir = project_root / "frida_scripts"
        
        logger.info(f"Frida analyzer initialized for package: {package_name}")
    
    
    def connect_device(self) -> bool:
        """
        Connect to Android device
        
        Returns:
            True if connected successfully
        """
        if not FRIDA_AVAILABLE:
            return False
        
        try:
            # Get device
            if self.device_id:
                self.device = frida.get_device(self.device_id)
            else:
                self.device = frida.get_usb_device(timeout=5)
            
            self.results['device_connected'] = True
            logger.info(f"Connected to device: {self.device.name}")
            return True
        
        except frida.TimedOutError:
            logger.error("Timeout connecting to device. Is USB debugging enabled?")
            return False
        except frida.ServerNotRunningError:
            logger.error("Frida server not running on device. Install frida-server.")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to device: {e}")
            return False
    
    
    def attach_to_app(self) -> bool:
        """
        Attach to running app or spawn it
        
        Returns:
            True if attached successfully
        """
        if not self.device:
            logger.error("Device not connected")
            return False
        
        try:
            # Try to attach to running process
            try:
                pid = self.device.get_process(self.package_name).pid
                self.session = self.device.attach(pid)
                logger.info(f"Attached to running process: {self.package_name} (PID: {pid})")
            except frida.ProcessNotFoundError:
                # Spawn the app
                pid = self.device.spawn([self.package_name])
                self.session = self.device.attach(pid)
                self.device.resume(pid)
                logger.info(f"Spawned and attached to: {self.package_name} (PID: {pid})")
            
            self.results['app_running'] = True
            return True
        
        except Exception as e:
            logger.error(f"Failed to attach to app: {e}")
            return False
    
    
    def load_hooks(self) -> bool:
        """
        Load Frida hooks for monitoring
        
        Returns:
            True if hooks loaded successfully
        """
        if not self.session:
            logger.error("No active session")
            return False
        
        try:
            # Load main hook script
            hook_script = self._generate_hook_script()
            
            # Create and load script
            self.script = self.session.create_script(hook_script)
            self.script.on('message', self._on_message)
            self.script.load()
            
            self.results['hooks_installed'] = True
            logger.info("Frida hooks installed successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to load hooks: {e}")
            return False
    
    
    def _generate_hook_script(self) -> str:
        """
        Generate Frida JavaScript hook script
        
        Returns:
            JavaScript code as string
        """
        # Check if custom script exists
        custom_script_path = self.scripts_dir / "hooks.js"
        if custom_script_path.exists():
            with open(custom_script_path, 'r') as f:
                return f.read()
        
        # Default inline hooks
        return """
// AndroSleuth Frida Hooks

// Crypto API Monitoring
Java.perform(function() {
    console.log("[*] Hooking Crypto APIs...");
    
    // javax.crypto.Cipher
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
        send({
            type: 'crypto',
            api: 'Cipher.getInstance',
            transformation: transformation,
            timestamp: Date.now()
        });
        return this.getInstance(transformation);
    };
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        send({
            type: 'crypto',
            api: 'Cipher.doFinal',
            input_size: input.length,
            timestamp: Date.now()
        });
        return this.doFinal(input);
    };
    
    // MessageDigest (Hashing)
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        send({
            type: 'crypto',
            api: 'MessageDigest.getInstance',
            algorithm: algorithm,
            timestamp: Date.now()
        });
        return this.getInstance(algorithm);
    };
});

// Network Monitoring
Java.perform(function() {
    console.log("[*] Hooking Network APIs...");
    
    // HttpURLConnection
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.setRequestMethod.implementation = function(method) {
        var url = this.getURL().toString();
        send({
            type: 'network',
            api: 'HttpURLConnection',
            method: method,
            url: url,
            timestamp: Date.now()
        });
        return this.setRequestMethod(method);
    };
    
    // OkHttp
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");
        
        OkHttpClient.newCall.implementation = function(request) {
            var url = request.url().toString();
            var method = request.method();
            send({
                type: 'network',
                api: 'OkHttp',
                method: method,
                url: url,
                timestamp: Date.now()
            });
            return this.newCall(request);
        };
    } catch(e) {
        console.log("[-] OkHttp not found");
    }
});

// File Operations
Java.perform(function() {
    console.log("[*] Hooking File APIs...");
    
    // FileOutputStream
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function(path, append) {
        send({
            type: 'file',
            api: 'FileOutputStream',
            path: path,
            mode: append ? 'append' : 'write',
            timestamp: Date.now()
        });
        return this.$init(path, append);
    };
    
    // FileInputStream
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
        send({
            type: 'file',
            api: 'FileInputStream',
            path: path,
            mode: 'read',
            timestamp: Date.now()
        });
        return this.$init(path);
    };
});

// Runtime.exec (Command Execution)
Java.perform(function() {
    console.log("[*] Hooking Runtime.exec...");
    
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        send({
            type: 'exec',
            api: 'Runtime.exec',
            command: cmd,
            severity: 'HIGH',
            timestamp: Date.now()
        });
        return this.exec(cmd);
    };
    
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
        send({
            type: 'exec',
            api: 'Runtime.exec',
            command: cmdarray.join(' '),
            severity: 'HIGH',
            timestamp: Date.now()
        });
        return this.exec(cmdarray);
    };
});

// SMS Operations
Java.perform(function() {
    console.log("[*] Hooking SMS APIs...");
    
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.implementation = function(dest, scAddr, text, sentIntent, deliveryIntent) {
            send({
                type: 'sms',
                api: 'SmsManager.sendTextMessage',
                destination: dest,
                text_length: text.length,
                severity: 'CRITICAL',
                timestamp: Date.now()
            });
            return this.sendTextMessage(dest, scAddr, text, sentIntent, deliveryIntent);
        };
    } catch(e) {
        console.log("[-] SmsManager not accessible");
    }
});

// Location Access
Java.perform(function() {
    console.log("[*] Hooking Location APIs...");
    
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        LocationManager.getLastKnownLocation.implementation = function(provider) {
            send({
                type: 'location',
                api: 'LocationManager.getLastKnownLocation',
                provider: provider,
                severity: 'MEDIUM',
                timestamp: Date.now()
            });
            return this.getLastKnownLocation(provider);
        };
    } catch(e) {
        console.log("[-] LocationManager not accessible");
    }
});

// Dynamic Code Loading
Java.perform(function() {
    console.log("[*] Hooking DexClassLoader...");
    
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libraryPath, parent) {
            send({
                type: 'dynamic_load',
                api: 'DexClassLoader',
                dex_path: dexPath,
                severity: 'HIGH',
                timestamp: Date.now()
            });
            return this.$init(dexPath, optimizedDir, libraryPath, parent);
        };
    } catch(e) {
        console.log("[-] DexClassLoader not accessible");
    }
});

// SSL Pinning Detection
Java.perform(function() {
    console.log("[*] Checking SSL Pinning...");
    
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
            send({
                type: 'ssl_pinning',
                api: 'CertificatePinner.check',
                hostname: hostname,
                info: 'SSL pinning detected',
                timestamp: Date.now()
            });
            return this.check(hostname, peerCerts);
        };
    } catch(e) {
        console.log("[-] No SSL pinning detected");
    }
});

console.log("[+] All hooks installed successfully");
"""
    
    
    def _on_message(self, message, data):
        """
        Handle messages from Frida script
        
        Args:
            message: Message dictionary
            data: Optional binary data
        """
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type', 'unknown')
            
            # Categorize and store
            if msg_type == 'network':
                self.results['network_requests'].append(payload)
                logger.debug(f"Network: {payload.get('method')} {payload.get('url')}")
            
            elif msg_type == 'file':
                self.results['file_operations'].append(payload)
                logger.debug(f"File: {payload.get('mode')} {payload.get('path')}")
            
            elif msg_type == 'crypto':
                self.results['crypto_operations'].append(payload)
                logger.debug(f"Crypto: {payload.get('api')}")
            
            elif msg_type in ['exec', 'sms', 'dynamic_load']:
                self.results['suspicious_behavior'].append(payload)
                severity = payload.get('severity', 'MEDIUM')
                logger.warning(f"[{severity}] Suspicious: {payload.get('api')}")
            
            # Store all API calls
            self.results['api_calls'].append(payload)
        
        elif message['type'] == 'error':
            logger.error(f"Frida script error: {message['description']}")
    
    
    def monitor(self, duration: int = 30):
        """
        Monitor app for specified duration
        
        Args:
            duration: Monitoring duration in seconds
        """
        if not self.script:
            logger.error("Hooks not loaded")
            return
        
        logger.info(f"Monitoring for {duration} seconds...")
        logger.info("Interact with the app to trigger behaviors...")
        
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            logger.info("Monitoring interrupted by user")
        
        logger.info("Monitoring complete")
    
    
    def analyze(self, duration: int = 30) -> Dict[str, Any]:
        """
        Full analysis workflow
        
        Args:
            duration: Monitoring duration in seconds
        
        Returns:
            Analysis results
        """
        if not FRIDA_AVAILABLE:
            logger.warning("Frida analysis skipped (not installed)")
            return self.results
        
        # Connect to device
        if not self.connect_device():
            return self.results
        
        # Attach to app
        if not self.attach_to_app():
            return self.results
        
        # Load hooks
        if not self.load_hooks():
            return self.results
        
        # Monitor
        self.monitor(duration)
        
        # Calculate threat score
        self._calculate_threat_score()
        
        return self.results
    
    
    def _calculate_threat_score(self):
        """Calculate threat score based on detected behaviors"""
        score = 0
        
        # Suspicious behaviors (critical)
        for behavior in self.results['suspicious_behavior']:
            if behavior.get('severity') == 'CRITICAL':
                score += 30
            elif behavior.get('severity') == 'HIGH':
                score += 20
            else:
                score += 10
        
        # Excessive network requests to unknown domains
        suspicious_domains = [req for req in self.results['network_requests'] 
                            if not any(d in req.get('url', '') for d in ['google', 'facebook', 'twitter'])]
        if len(suspicious_domains) > 10:
            score += 15
        
        # File operations in sensitive locations
        sensitive_paths = ['/data/data', '/sdcard', '/system']
        sensitive_ops = [op for op in self.results['file_operations']
                        if any(path in op.get('path', '') for path in sensitive_paths)]
        if len(sensitive_ops) > 5:
            score += 10
        
        # Crypto operations (not necessarily bad, but noteworthy)
        if len(self.results['crypto_operations']) > 20:
            score += 5
        
        self.results['threat_score'] = min(score, 100)
    
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get analysis summary
        
        Returns:
            Summary dictionary
        """
        return {
            'frida_available': self.results['frida_available'],
            'device_connected': self.results['device_connected'],
            'app_running': self.results['app_running'],
            'hooks_installed': self.results['hooks_installed'],
            'total_api_calls': len(self.results['api_calls']),
            'network_requests': len(self.results['network_requests']),
            'file_operations': len(self.results['file_operations']),
            'crypto_operations': len(self.results['crypto_operations']),
            'suspicious_behaviors': len(self.results['suspicious_behavior']),
            'threat_score': self.results['threat_score']
        }
    
    
    def get_detailed_results(self) -> Dict[str, Any]:
        """
        Get detailed analysis results
        
        Returns:
            Detailed results dictionary
        """
        return self.results
    
    
    def detach(self):
        """Detach from app and cleanup"""
        if self.session:
            self.session.detach()
            logger.info("Detached from app")
