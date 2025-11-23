# YARA Rules for AndroSleuth

This directory contains custom YARA rules for detecting malicious behavior in Android APK files.

## 📁 Rule Files

### `android_malware.yar`
Comprehensive malware detection rules including:
- **Trojans**: Generic trojan indicators, banking trojans, fake installers
- **Spyware**: SMS stealers, location trackers, keyloggers
- **Ransomware**: Screen lockers, file encryptors
- **Backdoors**: Remote access trojans, command & control
- **Data Exfiltration**: Contact/SMS/photo theft
- **Fraud**: Premium SMS fraud
- **Exploits**: Privilege escalation attempts
- **Miners**: Cryptocurrency mining malware
- **Adware**: Aggressive advertising behavior

### `android_packers.yar`
Commercial and custom packer detection:
- Bangcle/SecShell
- Qihoo 360
- Tencent Legu
- Baidu Protect
- Alibaba MobiSec
- DexProtector

## 🎯 Rule Metadata

Each rule includes metadata:
```yara
meta:
    description = "Human-readable description"
    author = "AndroSleuth"
    severity = "critical|high|medium|low"
    category = "trojan|spyware|ransomware|etc"
```

## 📊 Severity Levels

- **Critical**: Immediate threat (ransomware, banking trojans, keyloggers)
- **High**: Dangerous behavior (spyware, backdoors, data exfiltration)
- **Medium**: Suspicious activity (aggressive adware, miners)
- **Low**: Common obfuscation (legitimate packers)

## 🔧 Usage

AndroSleuth automatically loads all `.yar` and `.yara` files from this directory.

### Manual Testing
```bash
# Test a rule file
yara android_malware.yar /path/to/apk

# Test all rules
yara -r . /path/to/apk
```

### Custom Rules

Add your own rules to this directory. They will be automatically compiled and loaded.

Example:
```yara
rule My_Custom_Detection
{
    meta:
        description = "My custom malware pattern"
        author = "Your Name"
        severity = "high"
        category = "trojan"
    
    strings:
        $suspicious1 = "malicious_string"
        $suspicious2 = /regex_pattern/
    
    condition:
        any of them
}
```

## 📚 Resources

- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA-Python](https://github.com/VirusTotal/yara-python)
- [Android Malware Samples](https://github.com/ashishb/android-malware)
- [APKiD Rules](https://github.com/rednaga/APKiD)

## ⚠️ Legal Notice

These rules are for **educational and research purposes only**. Use responsibly and legally.

## 🤝 Contributing

Contributions of new rules are welcome! Please ensure:
1. Rules are well-documented
2. False positive rate is minimized
3. Severity is appropriate
4. Test against known samples
