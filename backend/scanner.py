"""
Core Ransomware Scanner Engine
Performs: Static Analysis, YARA Matching, Hash Lookup,
         Entropy Analysis, String Analysis, Import Analysis
"""

import os
import re
import json
import math
import hashlib
import struct
import logging
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    logger.warning("pefile not installed. PE analysis will be limited.")

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python not installed. YARA scanning disabled.")


class RansomwareScanner:
    """Main scanner class that orchestrates all detection methods"""

    def __init__(self, use_yara=True):
        self.use_yara = use_yara and HAS_YARA
        self.yara_rules = None
        self.known_hashes = {}

        # Load YARA rules
        if self.use_yara:
            self._load_yara_rules()

        # Load known malware hashes
        self._load_known_hashes()

        # Suspicious strings commonly found in ransomware
        self.ransom_strings = [
            # Ransom notes
            b'your files have been encrypted',
            b'your personal files are encrypted',
            b'all your files have been encrypted',
            b'your documents, photos, databases',
            b'to decrypt your files',
            b'to recover your files',
            b'pay the ransom',
            b'bitcoin',
            b'btc wallet',
            b'send bitcoin',
            b'decrypt',
            b'decryptor',
            b'recovery key',
            b'private key',
            b'unlock your files',
            b'your files are locked',
            b'ransomware',
            b'ransom',
            b'pay to',
            b'payment',
            b'deadline',
            b'countdown',
            b'tor browser',
            b'.onion',
            b'dark web',
            b'darknet',
            b'README_DECRYPT',
            b'HOW_TO_DECRYPT',
            b'HOW_TO_RECOVER',
            b'DECRYPT_INSTRUCTION',
            b'RECOVERY_INSTRUCTIONS',
            b'!!! READ ME !!!',
            b'YOUR FILES ARE ENCRYPTED',
            b'ATTENTION!',
            b'WARNING!',
            b'All your files are encrypted',
        ]

        # Crypto API strings
        self.crypto_apis = [
            b'CryptEncrypt',
            b'CryptDecrypt',
            b'CryptGenKey',
            b'CryptDeriveKey',
            b'CryptImportKey',
            b'CryptExportKey',
            b'CryptAcquireContext',
            b'CryptCreateHash',
            b'CryptHashData',
            b'CryptDestroyKey',
            b'CryptReleaseContext',
            b'BCryptEncrypt',
            b'BCryptDecrypt',
            b'BCryptGenerateSymmetricKey',
            b'AES',
            b'RSA',
            b'CryptoAPI',
            b'AES-256',
            b'RSA-2048',
            b'RSA-4096',
            b'Rijndael',
            b'Blowfish',
        ]

        # Suspicious file operation strings
        self.file_ops_strings = [
            b'vssadmin',
            b'vssadmin delete shadows',
            b'shadow copy',
            b'delete shadows /all',
            b'wmic shadowcopy delete',
            b'bcdedit',
            b'bcdedit /set',
            b'recoveryenabled no',
            b'wbadmin delete catalog',
            b'cmd.exe /c',
            b'powershell',
            b'Invoke-Expression',
            b'DownloadString',
            b'Net.WebClient',
            b'Start-Process',
            b'IEX',
        ]

        # File extensions targeted by ransomware
        self.target_extensions = [
            b'.doc', b'.docx', b'.xls', b'.xlsx', b'.ppt', b'.pptx',
            b'.pdf', b'.jpg', b'.jpeg', b'.png', b'.gif', b'.bmp',
            b'.zip', b'.rar', b'.7z', b'.tar', b'.gz',
            b'.sql', b'.mdb', b'.accdb', b'.dbf', b'.sqlite',
            b'.psd', b'.ai', b'.cdr', b'.dwg', b'.dxf',
            b'.mp3', b'.mp4', b'.avi', b'.mkv', b'.mov',
            b'.cpp', b'.java', b'.py', b'.cs', b'.php',
            b'.html', b'.css', b'.js', b'.xml', b'.json',
            b'.txt', b'.csv', b'.rtf', b'.odt',
            b'.wallet', b'.dat', b'.key', b'.pem',
        ]

        # Suspicious import functions
        self.suspicious_imports = {
            'file_system': [
                'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile',
                'DeleteFileA', 'DeleteFileW', 'MoveFileA', 'MoveFileW',
                'CopyFileA', 'CopyFileW', 'FindFirstFileA', 'FindFirstFileW',
                'FindNextFileA', 'FindNextFileW', 'GetLogicalDriveStrings',
                'GetDriveTypeA', 'GetDriveTypeW', 'SetFileAttributesA',
                'RemoveDirectoryA', 'RemoveDirectoryW',
            ],
            'crypto': [
                'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptDeriveKey',
                'CryptImportKey', 'CryptExportKey', 'CryptAcquireContextA',
                'CryptAcquireContextW', 'CryptCreateHash', 'CryptHashData',
                'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey',
                'BCryptOpenAlgorithmProvider',
            ],
            'process': [
                'CreateProcessA', 'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW',
                'WinExec', 'CreateThread', 'CreateRemoteThread',
                'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
                'OpenProcess', 'TerminateProcess',
            ],
            'network': [
                'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA',
                'HttpSendRequestA', 'URLDownloadToFileA', 'URLDownloadToFileW',
                'WSAStartup', 'connect', 'send', 'recv', 'socket',
            ],
            'registry': [
                'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA',
                'RegCreateKeyExW', 'RegOpenKeyExA', 'RegDeleteKeyA',
            ],
            'anti_debug': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'NtQueryInformationProcess', 'OutputDebugStringA',
                'GetTickCount', 'QueryPerformanceCounter',
            ]
        }

    def _load_yara_rules(self):
        """Load YARA rules from file"""
        rules_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'yara_rules',
            'ransomware_rules.yar'
        )
        try:
            if os.path.exists(rules_path):
                self.yara_rules = yara.compile(filepath=rules_path)
                logger.info(f"YARA rules loaded from {rules_path}")
            else:
                logger.warning(f"YARA rules file not found: {rules_path}")
                self.yara_rules = None
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self.yara_rules = None

    def _load_known_hashes(self):
        """Load known ransomware hashes"""
        hashes_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'signatures',
            'known_hashes.json'
        )
        try:
            if os.path.exists(hashes_path):
                with open(hashes_path, 'r') as f:
                    self.known_hashes = json.load(f)
                logger.info(f"Loaded {len(self.known_hashes)} known hashes")
            else:
                logger.warning(f"Known hashes file not found: {hashes_path}")
                self.known_hashes = {}
        except Exception as e:
            logger.error(f"Failed to load known hashes: {e}")
            self.known_hashes = {}

    # ================================================================
    # 1) STATIC ANALYSIS (PE Header)
    # ================================================================
    def static_analysis(self, filepath):
        """Analyze PE file headers and structure"""
        result = {
            'is_pe': False,
            'is_suspicious': False,
            'risk_score': 0,
            'severity': 'low',
            'indicators': [],
            'pe_info': {}
        }

        if not HAS_PEFILE:
            result['error'] = 'pefile module not installed'
            return result

        try:
            pe = pefile.PE(filepath)
            result['is_pe'] = True

            # Basic PE info
            result['pe_info'] = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'characteristics': hex(pe.FILE_HEADER.Characteristics),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            }

            risk = 0

            # Check for suspicious section names
            suspicious_section_names = ['.UPX', 'UPX0', 'UPX1', '.aspack', '.adata',
                                       '.nsp0', '.nsp1', '.themida', '.vmp0', '.vmp1',
                                       '.petite', '.yP', '.packed']
            sections_info = []
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_entropy = section.get_entropy()
                sections_info.append({
                    'name': section_name,
                    'entropy': round(section_entropy, 2),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData
                })

                if section_name in suspicious_section_names:
                    risk += 15
                    result['indicators'].append(f'Suspicious section name: {section_name}')

                # High entropy in section
                if section_entropy > 7.0:
                    risk += 10
                    result['indicators'].append(
                        f'High entropy section: {section_name} ({section_entropy:.2f})'
                    )

                # Section size mismatch (packing indicator)
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    risk += 10
                    result['indicators'].append(
                        f'Empty raw section with virtual size: {section_name}'
                    )

            result['pe_info']['sections'] = sections_info

            # Check number of sections (too few or too many)
            num_sections = pe.FILE_HEADER.NumberOfSections
            if num_sections <= 1:
                risk += 10
                result['indicators'].append(f'Unusually few sections: {num_sections}')
            elif num_sections > 10:
                risk += 5
                result['indicators'].append(f'Many sections: {num_sections}')

            # No import table (might be packed)
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') or len(pe.DIRECTORY_ENTRY_IMPORT) == 0:
                risk += 20
                result['indicators'].append('No import table found (likely packed)')

            # Check for TLS callbacks (anti-debug technique)
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                risk += 10
                result['indicators'].append('TLS callbacks present (possible anti-debug)')

            # Check for unsigned executable
            has_cert = False
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                has_cert = True
            if not has_cert:
                risk += 5
                result['indicators'].append('No digital signature')

            # Check for debug info
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                for debug in pe.DIRECTORY_ENTRY_DEBUG:
                    if debug.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                        result['pe_info']['debug_info'] = True

            # Check timestamp (very old or very new)
            timestamp = pe.FILE_HEADER.TimeDateStamp
            if timestamp == 0:
                risk += 10
                result['indicators'].append('Zero compilation timestamp (tampered)')
            elif timestamp > 2000000000:
                risk += 5
                result['indicators'].append('Future compilation timestamp')

            pe.close()

            result['risk_score'] = min(risk, 50)
            result['is_suspicious'] = risk >= 15

            if risk >= 30:
                result['severity'] = 'high'
            elif risk >= 15:
                result['severity'] = 'medium'

            return result

        except pefile.PEFormatError:
            result['is_pe'] = False
            result['pe_info'] = {'note': 'Not a valid PE file'}
            return result
        except Exception as e:
            result['error'] = str(e)
            return result

    # ================================================================
    # 2) YARA RULE SCANNING
    # ================================================================
    def yara_scan(self, filepath):
        """Scan file with YARA rules"""
        result = {
            'scanned': False,
            'matches': [],
            'rules_loaded': False
        }

        if not self.use_yara or not HAS_YARA:
            result['error'] = 'YARA not available'
            return result

        if self.yara_rules is None:
            result['error'] = 'No YARA rules loaded'
            return result

        try:
            matches = self.yara_rules.match(filepath)
            result['scanned'] = True
            result['rules_loaded'] = True

            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta if hasattr(match, 'meta') else {},
                    'strings_matched': []
                }
                if hasattr(match, 'strings'):
                    for s in match.strings[:20]:  # Limit to 20 string matches
                        try:
                            match_info['strings_matched'].append({
                                'offset': s[0] if isinstance(s, tuple) else getattr(s, 'offset', 0),
                                'identifier': s[1] if isinstance(s, tuple) else getattr(s, 'identifier', ''),
                                'data': str(s[2][:50]) if isinstance(s, tuple) else str(getattr(s, 'data', b'')[:50])
                            })
                        except Exception:
                            pass

                result['matches'].append(match_info)

            return result

        except Exception as e:
            result['error'] = str(e)
            return result

    # ================================================================
    # 3) HASH LOOKUP
    # ================================================================
    def hash_lookup(self, file_hash):
        """Look up file hash in known ransomware database"""
        result = {
            'hash': file_hash,
            'found': False,
            'malware_name': None,
            'malware_family': None,
            'severity': None
        }

        file_hash_lower = file_hash.lower()
        if file_hash_lower in self.known_hashes:
            info = self.known_hashes[file_hash_lower]
            result['found'] = True
            result['malware_name'] = info.get('name', 'Unknown')
            result['malware_family'] = info.get('family', 'Unknown')
            result['severity'] = info.get('severity', 'critical')
            result['description'] = info.get('description', '')

        return result

    # ================================================================
    # 4) ENTROPY ANALYSIS
    # ================================================================
    def entropy_analysis(self, filepath):
        """Analyze file entropy to detect encryption/packing"""
        result = {
            'entropy': 0,
            'is_suspicious': False,
            'risk_score': 0,
            'packed_sections': [],
            'file_entropy_distribution': []
        }

        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            if len(data) == 0:
                return result

            # Calculate overall file entropy
            overall_entropy = self._calculate_entropy(data)
            result['entropy'] = round(overall_entropy, 4)

            # Calculate entropy distribution (blocks)
            block_size = max(256, len(data) // 100)
            high_entropy_blocks = 0
            total_blocks = 0

            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                if len(block) < 64:
                    continue
                block_entropy = self._calculate_entropy(block)
                total_blocks += 1
                if block_entropy > 7.0:
                    high_entropy_blocks += 1

                # Sample every 10th block for distribution
                if total_blocks % 10 == 0:
                    result['file_entropy_distribution'].append({
                        'offset': i,
                        'entropy': round(block_entropy, 2)
                    })

            # PE section entropy
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(filepath)
                    for section in pe.sections:
                        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                        section_entropy = section.get_entropy()
                        if section_entropy > 7.0:
                            result['packed_sections'].append({
                                'name': section_name,
                                'entropy': round(section_entropy, 2)
                            })
                    pe.close()
                except Exception:
                    pass

            # Risk assessment
            risk = 0
            if overall_entropy > 7.5:
                risk += 25
                result['is_suspicious'] = True
            elif overall_entropy > 7.0:
                risk += 15
                result['is_suspicious'] = True
            elif overall_entropy > 6.5:
                risk += 5

            if total_blocks > 0:
                high_entropy_ratio = high_entropy_blocks / total_blocks
                if high_entropy_ratio > 0.8:
                    risk += 15
                elif high_entropy_ratio > 0.5:
                    risk += 10

            if len(result['packed_sections']) > 0:
                risk += 10 * len(result['packed_sections'])

            result['risk_score'] = min(risk, 40)

            return result

        except Exception as e:
            result['error'] = str(e)
            return result

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0

        byte_counts = Counter(data)
        length = len(data)
        entropy = 0

        for count in byte_counts.values():
            if count == 0:
                continue
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    # ================================================================
    # 5) STRING ANALYSIS
    # ================================================================
    def string_analysis(self, filepath):
        """Analyze strings in file for ransomware indicators"""
        result = {
            'is_suspicious': False,
            'risk_score': 0,
            'severity': 'low',
            'suspicious_strings': [],
            'crypto_apis': [],
            'ransom_indicators': [],
            'file_ops': [],
            'target_extensions_found': [],
            'urls_found': [],
            'emails_found': [],
            'bitcoin_addresses': []
        }

        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            data_lower = data.lower()
            risk = 0

            # Check for ransom note strings
            for rs in self.ransom_strings:
                if rs.lower() in data_lower:
                    result['ransom_indicators'].append(rs.decode('utf-8', errors='ignore'))
                    risk += 15

            # Check for crypto API strings
            for api in self.crypto_apis:
                if api in data:
                    result['crypto_apis'].append(api.decode('utf-8', errors='ignore'))
                    risk += 5

            # Check for suspicious file operations
            for fop in self.file_ops_strings:
                if fop.lower() in data_lower:
                    result['file_ops'].append(fop.decode('utf-8', errors='ignore'))
                    risk += 10

            # Count target extensions in binary
            ext_count = 0
            for ext in self.target_extensions:
                if ext in data_lower:
                    result['target_extensions_found'].append(ext.decode('utf-8', errors='ignore'))
                    ext_count += 1
            if ext_count >= 10:
                risk += 20
                result['suspicious_strings'].append(
                    f'File contains {ext_count} targeted file extensions'
                )
            elif ext_count >= 5:
                risk += 10

            # Extract URLs
            urls = re.findall(b'https?://[^\s<>"\'\\x00-\\x1f]{5,200}', data)
            result['urls_found'] = [u.decode('utf-8', errors='ignore') for u in urls[:20]]
            
            # Check for Tor/onion URLs
            tor_urls = [u for u in result['urls_found'] if '.onion' in u]
            if tor_urls:
                risk += 20
                result['suspicious_strings'].append(f'Tor/onion URLs found: {len(tor_urls)}')

            # Extract email addresses
            emails = re.findall(b'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', data)
            result['emails_found'] = list(set([e.decode('utf-8', errors='ignore') for e in emails[:10]]))

            # Bitcoin address pattern
            btc_pattern = re.findall(b'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', data)
            result['bitcoin_addresses'] = list(set([
                b.decode('utf-8', errors='ignore') for b in btc_pattern[:10]
            ]))
            if result['bitcoin_addresses']:
                risk += 15
                result['suspicious_strings'].append(
                    f'Bitcoin addresses found: {len(result["bitcoin_addresses"])}'
                )

            # Set results
            result['risk_score'] = min(risk, 50)
            result['is_suspicious'] = risk >= 15

            if risk >= 30:
                result['severity'] = 'high'
            elif risk >= 15:
                result['severity'] = 'medium'

            return result

        except Exception as e:
            result['error'] = str(e)
            return result

    # ================================================================
    # 6) IMPORT TABLE ANALYSIS
    # ================================================================
    def import_analysis(self, filepath):
        """Analyze PE import table for suspicious API calls"""
        result = {
            'is_suspicious': False,
            'risk_score': 0,
            'severity': 'low',
            'suspicious_imports': [],
            'import_categories': {},
            'total_imports': 0,
            'dlls_imported': []
        }

        if not HAS_PEFILE:
            result['error'] = 'pefile module not installed'
            return result

        try:
            pe = pefile.PE(filepath)

            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                result['note'] = 'No import table found'
                result['is_suspicious'] = True
                result['risk_score'] = 15
                pe.close()
                return result

            risk = 0
            all_imports = []

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                result['dlls_imported'].append(dll_name)

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        all_imports.append(func_name)

                        # Check against suspicious imports
                        for category, funcs in self.suspicious_imports.items():
                            if func_name in funcs:
                                if category not in result['import_categories']:
                                    result['import_categories'][category] = []
                                result['import_categories'][category].append(func_name)

            result['total_imports'] = len(all_imports)

            # Calculate risk based on categories
            categories_found = result['import_categories']

            # Having both crypto and file system imports is very suspicious
            if 'crypto' in categories_found and 'file_system' in categories_found:
                risk += 25
                result['suspicious_imports'].append(
                    'Combines cryptographic and file system operations'
                )

            # Network + crypto = exfiltration/C2 communication
            if 'network' in categories_found and 'crypto' in categories_found:
                risk += 15
                result['suspicious_imports'].append(
                    'Network communication with encryption capability'
                )

            # Anti-debug imports
            if 'anti_debug' in categories_found:
                risk += 10
                result['suspicious_imports'].append(
                    'Anti-debugging techniques detected'
                )

            # Process manipulation
            if 'process' in categories_found:
                risk += 10
                result['suspicious_imports'].append(
                    'Process manipulation capabilities'
                )

            # Registry manipulation
            if 'registry' in categories_found:
                risk += 5
                result['suspicious_imports'].append(
                    'Registry modification capabilities'
                )

            pe.close()

            result['risk_score'] = min(risk, 50)
            result['is_suspicious'] = risk >= 15

            if risk >= 30:
                result['severity'] = 'high'
            elif risk >= 15:
                result['severity'] = 'medium'

            return result

        except pefile.PEFormatError:
            result['note'] = 'Not a valid PE file'
            return result
        except Exception as e:
            result['error'] = str(e)
            return result