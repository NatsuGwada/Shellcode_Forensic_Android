/*
    YARA Rules for Android Packer Detection
    AndroSleuth Project
*/

rule Android_Packer_Bangcle
{
    meta:
        description = "Bangcle/SecShell Packer"
        author = "AndroSleuth"
        severity = "medium"
        category = "packer"
    
    strings:
        $bangcle1 = "libsecexe.so" nocase
        $bangcle2 = "libsecmain.so" nocase
        $bangcle3 = "libDexHelper.so" nocase
        $bangcle4 = "com.secneo" nocase
        $bangcle5 = "bangcle" nocase
    
    condition:
        any of them
}

rule Android_Packer_Qihoo360
{
    meta:
        description = "Qihoo 360 Packer"
        author = "AndroSleuth"
        severity = "medium"
        category = "packer"
    
    strings:
        $qihoo1 = "libjiagu.so" nocase
        $qihoo2 = "libjiagu_art.so" nocase
        $qihoo3 = "libjiagu_x86.so" nocase
        $qihoo4 = "com.qihoo.util" nocase
        $qihoo5 = "com.stub.StubApp" nocase
    
    condition:
        any of them
}

rule Android_Packer_Tencent
{
    meta:
        description = "Tencent Packer"
        author = "AndroSleuth"
        severity = "medium"
        category = "packer"
    
    strings:
        $tencent1 = "libtup.so" nocase
        $tencent2 = "libshell.so" nocase
        $tencent3 = "com.tencent.StubShell" nocase
        $tencent4 = "tencent" nocase
        $tencent5 = "legu" nocase
    
    condition:
        any of them
}

rule Android_Packer_Baidu
{
    meta:
        description = "Baidu Packer"
        author = "AndroSleuth"
        severity = "medium"
        category = "packer"
    
    strings:
        $baidu1 = "libbaiduprotect.so" nocase
        $baidu2 = "com.baidu.protect" nocase
        $baidu3 = "baiduprotect" nocase
    
    condition:
        any of them
}

rule Android_Packer_Alibaba
{
    meta:
        description = "Alibaba Packer"
        author = "AndroSleuth"
        severity = "medium"
        category = "packer"
    
    strings:
        $ali1 = "libmobisec.so" nocase
        $ali2 = "com.alibaba.mobisecenhance" nocase
        $ali3 = "alibaba" nocase
    
    condition:
        any of them
}

rule Android_Packer_DexProtector
{
    meta:
        description = "DexProtector Commercial Packer"
        author = "AndroSleuth"
        severity = "low"
        category = "packer"
    
    strings:
        $dexp1 = "dexprotector" nocase
        $dexp2 = "libjni-obfuscator.so" nocase
    
    condition:
        any of them
}
