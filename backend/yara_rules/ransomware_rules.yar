/*
    YARA Rules for Ransomware Detection
    Covers: WannaCry, Petya/NotPetya, Locky, Cerber, CryptoLocker,
            Ryuk, GandCrab, Maze, REvil/Sodinokibi, Dharma, STOP/Djvu,
            LockBit, Conti, BlackCat/ALPHV, and generic patterns.
*/

rule Generic_Ransomware_Strings
{
    meta:
        description = "Detects generic ransomware strings"
        severity = "high"
        category = "ransomware"

    strings:
        $ransom1 = "your files have been encrypted" ascii wide nocase
        $ransom2 = "your personal files are encrypted" ascii wide nocase
        $ransom3 = "all your files have been encrypted" ascii wide nocase
        $ransom4 = "to decrypt your files" ascii wide nocase
        $ransom5 = "send bitcoin" ascii wide nocase
        $ransom6 = "pay the ransom" ascii wide nocase
        $ransom7 = "decrypt your files" ascii wide nocase
        $ransom8 = "recovery key" ascii wide nocase
        $ransom9 = "unlock your files" ascii wide nocase
        $ransom10 = "your files are locked" ascii wide nocase
        $ransom11 = "HOW_TO_DECRYPT" ascii wide nocase
        $ransom12 = "DECRYPT_INSTRUCTION" ascii wide nocase
        $ransom13 = "README_DECRYPT" ascii wide nocase
        $ransom14 = "RECOVERY_INSTRUCTIONS" ascii wide nocase
        $ransom15 = "HOW TO RECOVER" ascii wide nocase
        $ransom16 = "files have been locked" ascii wide nocase

    condition:
        any of them
}

rule Ransomware_Crypto_APIs
{
    meta:
        description = "Detects use of Windows Crypto API commonly used by ransomware"
        severity = "medium"
        category = "crypto"

    strings:
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "CryptDeriveKey" ascii
        $api4 = "CryptImportKey" ascii
        $api5 = "CryptAcquireContextA" ascii
        $api6 = "CryptAcquireContextW" ascii
        $api7 = "BCryptEncrypt" ascii
        $api8 = "BCryptGenerateSymmetricKey" ascii
        $api9 = "BCryptOpenAlgorithmProvider" ascii

        $file1 = "FindFirstFileA" ascii
        $file2 = "FindFirstFileW" ascii
        $file3 = "FindNextFileA" ascii
        $file4 = "FindNextFileW" ascii
        $file5 = "WriteFile" ascii
        $file6 = "CreateFileA" ascii
        $file7 = "CreateFileW" ascii

    condition:
        2 of ($api*) and 2 of ($file*)
}

rule Ransomware_Shadow_Delete
{
    meta:
        description = "Detects Volume Shadow Copy deletion - common ransomware behavior"
        severity = "critical"
        category = "shadow_delete"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy delete" ascii wide nocase
        $vss4 = "delete shadows /all" ascii wide nocase
        $vss5 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $vss6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $vss7 = "wbadmin delete catalog" ascii wide nocase
        $vss8 = "Delete Shadows /All /Quiet" ascii wide nocase
        $vss9 = "vssadmin resize shadowstorage" ascii wide nocase

    condition:
        any of them
}

rule Ransomware_File_Extensions
{
    meta:
        description = "Detects file containing many targeted file extensions"
        severity = "medium"
        category = "file_targeting"

    strings:
        $ext1 = ".doc" ascii wide
        $ext2 = ".docx" ascii wide
        $ext3 = ".xls" ascii wide
        $ext4 = ".xlsx" ascii wide
        $ext5 = ".pdf" ascii wide
        $ext6 = ".ppt" ascii wide
        $ext7 = ".pptx" ascii wide
        $ext8 = ".jpg" ascii wide
        $ext9 = ".png" ascii wide
        $ext10 = ".zip" ascii wide
        $ext11 = ".rar" ascii wide
        $ext12 = ".sql" ascii wide
        $ext13 = ".mdb" ascii wide
        $ext14 = ".psd" ascii wide
        $ext15 = ".dwg" ascii wide
        $ext16 = ".mp3" ascii wide
        $ext17 = ".mp4" ascii wide
        $ext18 = ".wallet" ascii wide
        $ext19 = ".7z" ascii wide
        $ext20 = ".tar" ascii wide

    condition:
        12 of them
}

rule WannaCry_Ransomware
{
    meta:
        description = "Detects WannaCry / WanaCrypt0r ransomware"
        severity = "critical"
        family = "WannaCry"

    strings:
        $wc1 = "WanaCrypt0r" ascii wide nocase
        $wc2 = "WannaCryptor" ascii wide nocase
        $wc3 = "WANACRY!" ascii wide
        $wc4 = "WNcry@2ol7" ascii wide
        $wc5 = "WanaDecryptor" ascii wide nocase
        $wc6 = "@WanaDecryptor@" ascii wide
        $wc7 = ".WNCRY" ascii wide
        $wc8 = "msg/m_" ascii wide
        $wc9 = "tasksche.exe" ascii wide
        $wc10 = "mssecsvc.exe" ascii wide
        $wc11 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii wide
        $wc12 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii wide
        $wc13 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii wide

    condition:
        any of them
}

rule Petya_NotPetya
{
    meta:
        description = "Detects Petya/NotPetya/GoldenEye ransomware"
        severity = "critical"
        family = "Petya"

    strings:
        $p1 = "Petya" ascii wide nocase
        $p2 = "GoldenEye" ascii wide nocase
        $p3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0g" ascii
        $p4 = "wowsmith123456@posteo.net" ascii wide
        $p5 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" ascii wide
        $p6 = "CHKDSK is repairing" ascii wide
        $p7 = "Repairing file system on" ascii wide

    condition:
        any of them
}

rule Locky_Ransomware
{
    meta:
        description = "Detects Locky ransomware"
        severity = "critical"
        family = "Locky"

    strings:
        $l1 = "_Locky_recover_instructions" ascii wide nocase
        $l2 = ".locky" ascii wide
        $l3 = ".zepto" ascii wide
        $l4 = ".odin" ascii wide
        $l5 = ".aesir" ascii wide
        $l6 = ".osiris" ascii wide
        $l7 = ".thor" ascii wide
        $l8 = "Locky" ascii wide
        $l9 = "_WHAT_is" ascii wide

    condition:
        any of them
}

rule CryptoLocker
{
    meta:
        description = "Detects CryptoLocker ransomware"
        severity = "critical"
        family = "CryptoLocker"

    strings:
        $c1 = "CryptoLocker" ascii wide nocase
        $c2 = "Your personal files are encrypted" ascii wide nocase
        $c3 = "CryptoWall" ascii wide nocase
        $c4 = "DECRYPT_INSTRUCTION" ascii wide
        $c5 = "DECRYPT_ReadMe" ascii wide
        $c6 = "encrypted_files" ascii wide

    condition:
        any of them
}

rule Ryuk_Ransomware
{
    meta:
        description = "Detects Ryuk ransomware"
        severity = "critical"
        family = "Ryuk"

    strings:
        $r1 = "RyukReadMe" ascii wide nocase
        $r2 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
        $r3 = "RYK" ascii wide
        $r4 = ".RYK" ascii wide
        $r5 = "hrmlog" ascii wide
        $r6 = "HERMES" ascii wide
        $r7 = "No system is safe" ascii wide nocase
        $r8 = "balance of shadow universe" ascii wide nocase

    condition:
        any of them
}

rule GandCrab_Ransomware
{
    meta:
        description = "Detects GandCrab ransomware"
        severity = "critical"
        family = "GandCrab"

    strings:
        $g1 = "GANDCRAB" ascii wide nocase
        $g2 = "GandCrab" ascii wide
        $g3 = ".GDCB" ascii wide
        $g4 = ".CRAB" ascii wide
        $g5 = ".KRAB" ascii wide
        $g6 = "GDCB-DECRYPT" ascii wide
        $g7 = "CRAB-DECRYPT" ascii wide
        $g8 = "KRAB-DECRYPT" ascii wide
        $g9 = "pidor" ascii wide

    condition:
        any of them
}

rule REvil_Sodinokibi
{
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        severity = "critical"
        family = "REvil"

    strings:
        $re1 = "sodinokibi" ascii wide nocase
        $re2 = "REvil" ascii wide nocase
        $re3 = "sodin" ascii wide nocase
        $re4 = "{EXT}-readme.txt" ascii wide
        $re5 = "expand 32-byte k" ascii wide
        $re6 = "mpsvc.dll" ascii wide

    condition:
        any of them
}

rule LockBit_Ransomware
{
    meta:
        description = "Detects LockBit ransomware"
        severity = "critical"
        family = "LockBit"

    strings:
        $lb1 = "LockBit" ascii wide nocase
        $lb2 = ".lockbit" ascii wide nocase
        $lb3 = "Restore-My-Files.txt" ascii wide nocase
        $lb4 = "LockBit_Ransomware" ascii wide nocase
        $lb5 = "lockbit" ascii wide
        $lb6 = "LOCKBIT 2.0" ascii wide nocase
        $lb7 = "LOCKBIT 3.0" ascii wide nocase

    condition:
        any of them
}

rule Conti_Ransomware
{
    meta:
        description = "Detects Conti ransomware"
        severity = "critical"
        family = "Conti"

    strings:
        $co1 = "CONTI" ascii wide nocase
        $co2 = ".CONTI" ascii wide
        $co3 = "readme.txt" ascii wide
        $co4 = "contirecovery" ascii wide nocase
        $co5 = "All of your files are currently encrypted" ascii wide nocase

    condition:
        2 of them
}

rule BlackCat_ALPHV
{
    meta:
        description = "Detects BlackCat/ALPHV ransomware"
        severity = "critical"
        family = "BlackCat"

    strings:
        $bc1 = "ALPHV" ascii wide nocase
        $bc2 = "BlackCat" ascii wide nocase
        $bc3 = "RECOVER-" ascii wide
        $bc4 = "-FILES.txt" ascii wide
        $bc5 = "access_key" ascii wide
        $bc6 = "note_file_name" ascii wide

    condition:
        2 of them
}

rule STOP_Djvu_Ransomware
{
    meta:
        description = "Detects STOP/Djvu ransomware family"
        severity = "critical"
        family = "STOP_Djvu"

    strings:
        $sd1 = "_readme.txt" ascii wide
        $sd2 = "STOP" ascii wide
        $sd3 = "Djvu" ascii wide nocase
        $sd4 = "ATTENTION!" ascii wide
        $sd5 = "restorefiles@" ascii wide nocase
        $sd6 = "gorentos@bitmessage" ascii wide nocase
        $sd7 = "personal ID" ascii wide nocase

    condition:
        2 of them
}

rule Maze_Ransomware
{
    meta:
        description = "Detects Maze ransomware"
        severity = "critical"
        family = "Maze"

    strings:
        $m1 = "MAZE" ascii wide nocase
        $m2 = "maze" ascii wide
        $m3 = "DECRYPT-FILES.txt" ascii wide nocase
        $m4 = "mazedecrypt" ascii wide nocase

    condition:
        any of them
}

rule Dharma_Ransomware
{
    meta:
        description = "Detects Dharma/CrySis ransomware family"
        severity = "critical"
        family = "Dharma"

    strings:
        $d1 = "dharma" ascii wide nocase
        $d2 = "CrySis" ascii wide nocase
        $d3 = ".dharma" ascii wide
        $d4 = ".arena" ascii wide
        $d5 = ".bip" ascii wide
        $d6 = "FILES ENCRYPTED.txt" ascii wide nocase
        $d7 = "All FILES ENCRYPTED" ascii wide nocase

    condition:
        2 of them
}

rule Ransomware_Bitcoin_Payment
{
    meta:
        description = "Detects Bitcoin payment instructions often found in ransomware"
        severity = "high"
        category = "payment"

    strings:
        $btc1 = "bitcoin" ascii wide nocase
        $btc2 = "btc" ascii wide nocase
        $btc3 = "wallet" ascii wide nocase
        $btc4 = "payment" ascii wide nocase
        $btc5 = "tor browser" ascii wide nocase
        $btc6 = ".onion" ascii wide
        $addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii

        $decrypt1 = "decrypt" ascii wide nocase
        $decrypt2 = "encrypt" ascii wide nocase

    condition:
        ($addr and 1 of ($decrypt*)) or (2 of ($btc*) and 1 of ($decrypt*))
}

rule Ransomware_Persistence
{
    meta:
        description = "Detects ransomware persistence mechanisms"
        severity = "high"
        category = "persistence"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $sched1 = "schtasks" ascii wide nocase
        $sched2 = "/create" ascii wide nocase
        $sched3 = "SchTasks.exe" ascii wide nocase
        $startup = "Startup" ascii wide
        $task = "TaskScheduler" ascii wide

    condition:
        any of ($reg*) or (1 of ($sched*)) or ($startup and $task)
}

rule Packed_Suspicious_PE
{
    meta:
        description = "Detects potentially packed/obfuscated PE files"
        severity = "medium"
        category = "packing"

    strings:
        $upx = "UPX!" ascii
        $aspack = ".aspack" ascii
        $fsg = "FSG!" ascii
        $petite = ".petite" ascii
        $themida = ".themida" ascii
        $vmprotect = ".vmp0" ascii
        $mpress = ".MPRESS" ascii

    condition:
        uint16(0) == 0x5A4D and any of them
}