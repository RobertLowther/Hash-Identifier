#!/usr/bin/env python
# encoding: utf-8
# Hash Identifier
# By Zion3R
# www.Blackploit.com
# Root@Blackploit.com

from builtins import input
from sys import argv, exit
import subprocess
import os
import re

version = 1.2

logo='''   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v'''+str(version)+''' #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################'''

algorithms={"102020":"ADLER-32", "102040":"CRC-32", "102060":"CRC-32B", "101020":"CRC-16", "101040":"CRC-16-CCITT", "104020":"DES(Unix)", "101060":"FCS-16", "103040":"GHash-32-3", "103020":"GHash-32-5", "115060":"GOST R 34.11-94", "109100":"Haval-160", "109200":"Haval-160(HMAC)", "110040":"Haval-192", "110080":"Haval-192(HMAC)", "114040":"Haval-224", "114080":"Haval-224(HMAC)", "115040":"Haval-256", "115140":"Haval-256(HMAC)", "107080":"Lineage II C4", "106025":"Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))", "102080":"XOR-32", "105060":"MD5(Half)", "105040":"MD5(Middle)", "105020":"MySQL", "107040":"MD5(phpBB3)", "107060":"MD5(Unix)", "107020":"MD5(Wordpress)", "108020":"MD5(APR)", "106160":"Haval-128", "106165":"Haval-128(HMAC)", "106060":"MD2", "106120":"MD2(HMAC)", "106040":"MD4", "106100":"MD4(HMAC)", "106020":"MD5", "106080":"MD5(HMAC)", "106140":"MD5(HMAC(Wordpress))", "106029":"NTLM", "106027":"RAdmin v2.x", "106180":"RipeMD-128", "106185":"RipeMD-128(HMAC)", "106200":"SNEFRU-128", "106205":"SNEFRU-128(HMAC)", "106220":"Tiger-128", "106225":"Tiger-128(HMAC)", "106240":"md5($pass.$salt)", "106260":"md5($salt.'-'.md5($pass))", "106280":"md5($salt.$pass)", "106300":"md5($salt.$pass.$salt)", "106320":"md5($salt.$pass.$username)", "106340":"md5($salt.md5($pass))", "106360":"md5($salt.md5($pass).$salt)", "106380":"md5($salt.md5($pass.$salt))", "106400":"md5($salt.md5($salt.$pass))", "106420":"md5($salt.md5(md5($pass).$salt))", "106440":"md5($username.0.$pass)", "106460":"md5($username.LF.$pass)", "106480":"md5($username.md5($pass).$salt)", "106500":"md5(md5($pass))", "106520":"md5(md5($pass).$salt)", "106540":"md5(md5($pass).md5($salt))", "106560":"md5(md5($salt).$pass)", "106580":"md5(md5($salt).md5($pass))", "106600":"md5(md5($username.$pass).$salt)", "106620":"md5(md5(md5($pass)))", "106640":"md5(md5(md5(md5($pass))))", "106660":"md5(md5(md5(md5(md5($pass)))))", "106680":"md5(sha1($pass))", "106700":"md5(sha1(md5($pass)))", "106720":"md5(sha1(md5(sha1($pass))))", "106740":"md5(strtoupper(md5($pass)))", "109040":"MySQL5 - SHA-1(SHA-1($pass))", "109060":"MySQL 160bit - SHA-1(SHA-1($pass))", "109180":"RipeMD-160(HMAC)", "109120":"RipeMD-160", "109020":"SHA-1", "109140":"SHA-1(HMAC)", "109220":"SHA-1(MaNGOS)", "109240":"SHA-1(MaNGOS2)", "109080":"Tiger-160", "109160":"Tiger-160(HMAC)", "109260":"sha1($pass.$salt)", "109280":"sha1($salt.$pass)", "109300":"sha1($salt.md5($pass))", "109320":"sha1($salt.md5($pass).$salt)", "109340":"sha1($salt.sha1($pass))", "109360":"sha1($salt.sha1($salt.sha1($pass)))", "109380":"sha1($username.$pass)", "109400":"sha1($username.$pass.$salt)", "109420":"sha1(md5($pass))", "109440":"sha1(md5($pass).$salt)", "109460":"sha1(md5(sha1($pass)))", "109480":"sha1(sha1($pass))", "109500":"sha1(sha1($pass).$salt)", "109520":"sha1(sha1($pass).substr($pass,0,3))", "109540":"sha1(sha1($salt.$pass))", "109560":"sha1(sha1(sha1($pass)))", "109580":"sha1(strtolower($username).$pass)", "110020":"Tiger-192", "110060":"Tiger-192(HMAC)", "112020":"md5($pass.$salt) - Joomla", "113020":"SHA-1(Django)", "114020":"SHA-224", "114060":"SHA-224(HMAC)", "115080":"RipeMD-256", "115160":"RipeMD-256(HMAC)", "115100":"SNEFRU-256", "115180":"SNEFRU-256(HMAC)", "115200":"SHA-256(md5($pass))", "115220":"SHA-256(sha1($pass))", "115020":"SHA-256", "115120":"SHA-256(HMAC)", "116020":"md5($pass.$salt) - Joomla", "116040":"SAM - (LM_hash:NT_hash)", "117020":"SHA-256(Django)", "118020":"RipeMD-320", "118040":"RipeMD-320(HMAC)", "119020":"SHA-384", "119040":"SHA-384(HMAC)", "120020":"SHA-256", "121020":"SHA-384(Django)", "122020":"SHA-512", "122060":"SHA-512(HMAC)", "122040":"Whirlpool", "122080":"Whirlpool(HMAC)"}
john_types=['descrypt', 'bsdicrypt', 'md5crypt', 'md5crypt-long', 'bcrypt', 'scrypt', 'LM', 'AFS', 'tripcode', 'AndroidBackup', 'adxcrypt', 'agilekeychain', 'aix-ssha1', 'aix-ssha256', 'aix-ssha512', 'andOTP', 'ansible', 'argon2', 'as400-des', 'as400-ssha1', 'asa-md5', 'AxCrypt', 'AzureAD', 'BestCrypt', 'BestCryptVE4', 'bfegg', 'Bitcoin', 'BitLocker', 'bitshares', 'Bitwarden', 'BKS', 'Blackberry-ES10', 'WoWSRP', 'Blockchain', 'chap', 'Clipperz', 'cloudkeychain', 'dynamic_n', 'cq', 'CRC32', 'cryptoSafe', 'sha1crypt', 'sha256crypt', 'sha512crypt', 'Citrix_NS10', 'dahua', 'dashlane', 'diskcryptor', 'Django', 'django-scrypt', 'dmd5', 'dmg', 'dominosec', 'dominosec8', 'DPAPImk', 'dragonfly3-32', 'dragonfly3-64', 'dragonfly4-32', 'dragonfly4-64', 'Drupal7', 'eCryptfs', 'eigrp', 'electrum', 'EncFS', 'enpass', 'EPI', 'EPiServer', 'ethereum', 'fde', 'Fortigate256', 'Fortigate', 'FormSpring', 'FVDE', 'geli', 'gost', 'gpg', 'HAVAL-128-4', 'HAVAL-256-3', 'hdaa', 'hMailServer', 'hsrp', 'IKE', 'ipb2', 'itunes-backup', 'iwork', 'KeePass', 'keychain', 'keyring', 'keystore', 'known_hosts', 'krb4', 'krb5', 'krb5asrep', 'krb5pa-sha1', 'krb5tgs', 'krb5-17', 'krb5-18', 'krb5-3', 'kwallet', 'lp', 'lpcli', 'leet', 'lotus5', 'lotus85', 'LUKS', 'MD2', 'mdc2', 'MediaWiki', 'monero', 'money', 'MongoDB', 'scram', 'Mozilla', 'mscash', 'mscash2', 'MSCHAPv2', 'mschapv2-naive', 'krb5pa-md5', 'mssql', 'mssql05', 'mssql12', 'multibit', 'mysqlna', 'mysql-sha1', 'mysql', 'net-ah', 'nethalflm', 'netlm', 'netlmv2', 'net-md5', 'netntlmv2', 'netntlm', 'netntlm-naive', 'net-sha1', 'nk', 'notes', 'md5ns', 'nsec3', 'NT', 'o10glogon', 'o3logon', 'o5logon', 'ODF', 'Office', 'oldoffice', 'OpenBSD-SoftRAID', 'openssl-enc', 'oracle', 'oracle11', 'Oracle12C', 'osc', 'ospf', 'Padlock', 'Palshop', 'Panama', 'PBKDF2-HMAC-MD4', 'PBKDF2-HMAC-MD5', 'PBKDF2-HMAC-SHA1', 'PBKDF2-HMAC-SHA256', 'PBKDF2-HMAC-SHA512', 'PDF', 'PEM', 'pfx', 'pgpdisk', 'pgpsda', 'pgpwde', 'phpass', 'PHPS', 'PHPS2', 'pix-md5', 'PKZIP', 'po', 'postgres', 'PST', 'PuTTY', 'pwsafe', 'qnx', 'RACF', 'RACF-KDFAES', 'radius', 'RAdmin', 'RAKP', 'rar', 'RAR5', 'Raw-SHA512', 'Raw-Blake2', 'Raw-Keccak', 'Raw-Keccak-256', 'Raw-MD4', 'Raw-MD5', 'Raw-MD5u', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Raw-SHA224', 'Raw-SHA256', 'Raw-SHA3', 'Raw-SHA384', 'restic', 'ripemd-128', 'ripemd-160', 'rsvp', 'RVARY', 'Siemens-S7', 'Salted-SHA1', 'SSHA512', 'sapb', 'sapg', 'saph', 'sappse', 'securezip', '7z', 'Signal', 'SIP', 'skein-256', 'skein-512', 'skey', 'SL3', 'Snefru-128', 'Snefru-256', 'LastPass', 'SNMP', 'solarwinds', 'SSH', 'sspr', 'Stribog-256', 'Stribog-512', 'STRIP', 'SunMD5', 'SybaseASE', 'Sybase-PROP', 'tacacs-plus', 'tcp-md5', 'telegram', 'tezos', 'Tiger', 'tc_aes_xts', 'tc_ripemd160', 'tc_ripemd160boot', 'tc_sha512', 'tc_whirlpool', 'vdi', 'OpenVMS', 'vmx', 'VNC', 'vtp', 'wbb3', 'whirlpool', 'whirlpool0', 'whirlpool1', 'wpapsk', 'wpapsk-pmk', 'xmpp-scram', 'xsha', 'xsha512', 'zed', 'ZIP', 'ZipMonster', 'plaintext', 'has-160', 'HMAC-MD5', 'HMAC-SHA1', 'HMAC-SHA224', 'HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512', 'dummy', 'crypt']

john_relations = {
'102020': [],
'102040': ['CRC32'],
'102060': [],
'101020': [],
'101040': [],
'104020': ['descrypt', 'as400-des'],
'101060': [],
'103040': [],
'103020': [],
'115060': ['gost'],
'109100': [],
'109200': [],
'110040': [],
'110080': [],
'114040': [],
'114080': [],
'115040': [],
'115140': [],
'107080': [],
'106025': [],
'102080': [],
'105060': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'105040': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'105020': ['mysqlna', 'mysql-sha1', 'mysql'],
'107040': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'107060': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'107020': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'108020': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106160': [],
'106165': [],
'106060': ['MD2'],
'106120': ['MD2', 'mdc2'],
'106040': ['PBKDF2-HMAC-MD4', 'Raw-MD4'],
'106100': ['PBKDF2-HMAC-MD4', 'Raw-MD4'],
'106020': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106080': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106140': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106029': ['netntlmv2', 'netntlm', 'netntlm-naive'],
'106027': ['RAdmin'],
'106180': [],
'106185': [],
'106200': [],
'106205': [],
'106220': [],
'106225': [],
'106240': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106260': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106280': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106300': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106320': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106340': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106360': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106380': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106400': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106420': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106440': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106460': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106480': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106500': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106520': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106540': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106560': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106580': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106600': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106620': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106640': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106660': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106680': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106700': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106720': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'106740': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'109040': ['mysqlna', 'mysql-sha1', 'mysql'],
'109060': ['mysqlna', 'mysql-sha1', 'mysql'],
'109180': ['tc_ripemd160', 'tc_ripemd160boot'],
'109120': ['tc_ripemd160', 'tc_ripemd160boot'],
'109020': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109140': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109220': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109240': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109080': ['Tiger'],
'109160': ['Tiger'],
'109260': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109280': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109300': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109320': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109340': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109360': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109380': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109400': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109420': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109440': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109460': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109480': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109500': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109520': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109540': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109560': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'109580': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'110020': ['Tiger'],
'110060': ['Tiger'],
'112020': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'113020': ['aix-ssha1', 'as400-ssha1', 'sha1crypt', 'krb5pa-sha1', 'mysql-sha1', 'net-sha1', 'PBKDF2-HMAC-SHA1', 'Raw-SHA1', 'Raw-SHA1-AxCrypt', 'Raw-SHA1-Linkedin', 'Salted-SHA1', 'HMAC-SHA1'],
'114020': ['Raw-SHA224', 'HMAC-SHA224'],
'114060': ['Raw-SHA224', 'HMAC-SHA224'],
'115080': ['ripemd-160'],
'115160': ['ripemd-160'],
'115100': [],
'115180': [],
'115200': ['aix-ssha256', 'sha256crypt', 'PBKDF2-HMAC-SHA256', 'Raw-SHA256', 'HMAC-SHA256'],
'115220': ['aix-ssha256', 'sha256crypt', 'PBKDF2-HMAC-SHA256', 'Raw-SHA256', 'HMAC-SHA256'],
'115020': ['aix-ssha256', 'sha256crypt', 'PBKDF2-HMAC-SHA256', 'Raw-SHA256', 'HMAC-SHA256'],
'115120': ['aix-ssha256', 'sha256crypt', 'PBKDF2-HMAC-SHA256', 'Raw-SHA256', 'HMAC-SHA256'],
'116020': ['md5crypt', 'md5crypt-long', 'asa-md5', 'dmd5', 'krb5pa-md5', 'net-md5', 'md5ns', 'PBKDF2-HMAC-MD5', 'pix-md5', 'Raw-MD5', 'Raw-MD5u', 'SunMD5', 'tcp-md5', 'HMAC-MD5'],
'116040': ['LM'],
'117020': ['aix-ssha256', 'sha256crypt', 'PBKDF2-HMAC-SHA256', 'Raw-SHA256', 'HMAC-SHA256'],
'118020': [],
'118040': [],
'119020': ['Raw-SHA384', 'HMAC-SHA384'],
'119040': ['Raw-SHA384', 'HMAC-SHA384'],
'120020': ['aix-ssha256', 'sha256crypt', 'PBKDF2-HMAC-SHA256', 'Raw-SHA256', 'HMAC-SHA256'],
'121020': ['Raw-SHA384', 'HMAC-SHA384'],
'122020': ['aix-ssha512', 'sha512crypt', 'PBKDF2-HMAC-SHA512', 'Raw-SHA512', 'SSHA512', 'tc_sha512', 'xsha512', 'HMAC-SHA512'],
'122060': ['aix-ssha512', 'sha512crypt', 'PBKDF2-HMAC-SHA512', 'Raw-SHA512', 'SSHA512', 'tc_sha512', 'xsha512', 'HMAC-SHA512'],
'122040': ['tc_whirlpool', 'whirlpool', 'whirlpool0', 'whirlpool1'],
'122080': ['tc_whirlpool', 'whirlpool', 'whirlpool0', 'whirlpool1']
}

# hash.islower()  minusculas
# hash.isdigit()  numerico
# hash.isalpha()  letras
# hash.isalnum()  alfanumerico

def CRC16(hash, jerar):
    hs='4607'
    if len(hash)==len(hs) and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("101020")
def CRC16CCITT(hash, jerar):
    hs='3d08'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("101040")
def FCS16(hash, jerar):
    hs='0e5b'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("101060")

def CRC32(hash, jerar):
    hs='b33fd057'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("102040")
def ADLER32(hash, jerar):
    hs='0607cb42'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("102020")
def CRC32B(hash, jerar):
    hs='b764a0d9'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("102060")
def XOR32(hash, jerar):
    hs='0000003f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("102080")

def GHash323(hash, jerar):
    hs='80000000'
    if len(hash)==len(hs) and hash.isdigit()==True and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("103040")
def GHash325(hash, jerar):
    hs='85318985'
    if len(hash)==len(hs) and hash.isdigit()==True and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("103020")

def DESUnix(hash, jerar):
    hs='ZiY8YtDKXJwYQ'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False:
        jerar.append("104020")

def MD5Half(hash, jerar):
    hs='ae11fd697ec92c7c'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("105060")
def MD5Middle(hash, jerar):
    hs='7ec92c7c98de3fac'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("105040")
def MySQL(hash, jerar):
    hs='63cea4673fd25f46'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("105020")

def DomainCachedCredentials(hash, jerar):
    hs='f42005ec1afe77967cbc83dce1b4d714'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106025")
def Haval128(hash, jerar):
    hs='d6e3ec49aa0f138a619f27609022df10'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106160")
def Haval128HMAC(hash, jerar):
    hs='3ce8b0ffd75bc240fc7d967729cd6637'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106165")
def MD2(hash, jerar):
    hs='08bbef4754d98806c373f2cd7d9a43c4'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106060")
def MD2HMAC(hash, jerar):
    hs='4b61b72ead2b0eb0fa3b8a56556a6dca'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106120")
def MD4(hash, jerar):
    hs='a2acde400e61410e79dacbdfc3413151'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106040")
def MD4HMAC(hash, jerar):
    hs='6be20b66f2211fe937294c1c95d1cd4f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106100")
def MD5(hash, jerar):
    hs='ae11fd697ec92c7c98de3fac23aba525'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106020")
def MD5HMAC(hash, jerar):
    hs='d57e43d2c7e397bf788f66541d6fdef9'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106080")
def MD5HMACWordpress(hash, jerar):
    hs='3f47886719268dfa83468630948228f6'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106140")
def NTLM(hash, jerar):
    hs='cc348bace876ea440a28ddaeb9fd3550'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106029")
def RAdminv2x(hash, jerar):
    hs='baea31c728cbf0cd548476aa687add4b'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106027")
def RipeMD128(hash, jerar):
    hs='4985351cd74aff0abc5a75a0c8a54115'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106180")
def RipeMD128HMAC(hash, jerar):
    hs='ae1995b931cf4cbcf1ac6fbf1a83d1d3'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106185")
def SNEFRU128(hash, jerar):
    hs='4fb58702b617ac4f7ca87ec77b93da8a'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106200")
def SNEFRU128HMAC(hash, jerar):
    hs='59b2b9dcc7a9a7d089cecf1b83520350'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106205")
def Tiger128(hash, jerar):
    hs='c086184486ec6388ff81ec9f23528727'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106220")
def Tiger128HMAC(hash, jerar):
    hs='c87032009e7c4b2ea27eb6f99723454b'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106225")
def md5passsalt(hash, jerar):
    hs='5634cc3b922578434d6e9342ff5913f7'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106240")
def md5saltpass(hash, jerar):
    hs='22cc5ce1a1ef747cd3fa06106c148dfa'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106280")
def md5saltpasssalt(hash, jerar):
    hs='469e9cdcaff745460595a7a386c4db0c'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106300")
def md5saltpassusername(hash, jerar):
    hs='9ae20f88189f6e3a62711608ddb6f5fd'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106320")
def md5saltmd5pass(hash, jerar):
    hs='aca2a052962b2564027ee62933d2382f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106340")
def md5saltmd5passsalt(hash, jerar):
    hs='5b8b12ca69d3e7b2a3e2308e7bef3e6f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106380")
def md5saltmd5saltpass(hash, jerar):
    hs='d8f3b3f004d387086aae24326b575b23'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106400")
def md5saltmd5md5passsalt(hash, jerar):
    hs='81f181454e23319779b03d74d062b1a2'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106420")
def md5username0pass(hash, jerar):
    hs='e44a60f8f2106492ae16581c91edb3ba'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106440")
def md5usernameLFpass(hash, jerar):
    hs='654741780db415732eaee12b1b909119'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106460")
def md5usernamemd5passsalt(hash, jerar):
    hs='954ac5505fd1843bbb97d1b2cda0b98f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106480")
def md5md5pass(hash, jerar):
    hs='a96103d267d024583d5565436e52dfb3'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106500")
def md5md5passsalt(hash, jerar):
    hs='5848c73c2482d3c2c7b6af134ed8dd89'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106520")
def md5md5passmd5salt(hash, jerar):
    hs='8dc71ef37197b2edba02d48c30217b32'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106540")
def md5md5saltpass(hash, jerar):
    hs='9032fabd905e273b9ceb1e124631bd67'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106560")
def md5md5saltmd5pass(hash, jerar):
    hs='8966f37dbb4aca377a71a9d3d09cd1ac'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106580")
def md5md5usernamepasssalt(hash, jerar):
    hs='4319a3befce729b34c3105dbc29d0c40'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106600")
def md5md5md5pass(hash, jerar):
    hs='ea086739755920e732d0f4d8c1b6ad8d'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106620")
def md5md5md5md5pass(hash, jerar):
    hs='02528c1f2ed8ac7d83fe76f3cf1c133f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106640")
def md5md5md5md5md5pass(hash, jerar):
    hs='4548d2c062933dff53928fd4ae427fc0'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106660")
def md5sha1pass(hash, jerar):
    hs='cb4ebaaedfd536d965c452d9569a6b1e'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106680")
def md5sha1md5pass(hash, jerar):
    hs='099b8a59795e07c334a696a10c0ebce0'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106700")
def md5sha1md5sha1pass(hash, jerar):
    hs='06e4af76833da7cc138d90602ef80070'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106720")
def md5strtouppermd5pass(hash, jerar):
    hs='519de146f1a658ab5e5e2aa9b7d2eec8'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("106740")

def LineageIIC4(hash, jerar):
    hs='0x49a57f66bd3d5ba6abda5579c264a0e4'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True and hash[0:2].find('0x')==0:
        jerar.append("107080")
def MD5phpBB3(hash, jerar):
    hs='$H$9kyOtE8CDqMJ44yfn9PFz2E.L2oVzL1'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:3].find('$H$')==0:
        jerar.append("107040")
def MD5Unix(hash, jerar):
    hs='$1$cTuJH0Ju$1J8rI.mJReeMvpKUZbSlY/'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:3].find('$1$')==0:
        jerar.append("107060")
def MD5Wordpress(hash, jerar):
    hs='$P$BiTOhOj3ukMgCci2juN0HRbCdDRqeh.'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:3].find('$P$')==0:
        jerar.append("107020")

def MD5APR(hash, jerar):
    hs='$apr1$qAUKoKlG$3LuCncByN76eLxZAh/Ldr1'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash[0:4].find('$apr')==0:
        jerar.append("108020")

def Haval160(hash, jerar):
    hs='a106e921284dd69dad06192a4411ec32fce83dbb'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109100")
def Haval160HMAC(hash, jerar):
    hs='29206f83edc1d6c3f680ff11276ec20642881243'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109200")
def MySQL5(hash, jerar):
    hs='9bb2fb57063821c762cc009f7584ddae9da431ff'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109040")
def MySQL160bit(hash, jerar):
    hs='*2470c0c06dee42fd1618bb99005adca2ec9d1e19'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:1].find('*')==0:
        jerar.append("109060")
def RipeMD160(hash, jerar):
    hs='dc65552812c66997ea7320ddfb51f5625d74721b'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109120")
def RipeMD160HMAC(hash, jerar):
    hs='ca28af47653b4f21e96c1235984cb50229331359'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109180")
def SHA1(hash, jerar):
    hs='4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109020")
def SHA1HMAC(hash, jerar):
    hs='6f5daac3fee96ba1382a09b1ba326ca73dccf9e7'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109140")
def SHA1MaNGOS(hash, jerar):
    hs='a2c0cdb6d1ebd1b9f85c6e25e0f8732e88f02f96'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109220")
def SHA1MaNGOS2(hash, jerar):
    hs='644a29679136e09d0bd99dfd9e8c5be84108b5fd'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109240")
def Tiger160(hash, jerar):
    hs='c086184486ec6388ff81ec9f235287270429b225'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109080")
def Tiger160HMAC(hash, jerar):
    hs='6603161719da5e56e1866e4f61f79496334e6a10'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109160")
def sha1passsalt(hash, jerar):
    hs='f006a1863663c21c541c8d600355abfeeaadb5e4'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109260")
def sha1saltpass(hash, jerar):
    hs='299c3d65a0dcab1fc38421783d64d0ecf4113448'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109280")
def sha1saltmd5pass(hash, jerar):
    hs='860465ede0625deebb4fbbedcb0db9dc65faec30'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109300")
def sha1saltmd5passsalt(hash, jerar):
    hs='6716d047c98c25a9c2cc54ee6134c73e6315a0ff'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109320")
def sha1saltsha1pass(hash, jerar):
    hs='58714327f9407097c64032a2fd5bff3a260cb85f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109340")
def sha1saltsha1saltsha1pass(hash, jerar):
    hs='cc600a2903130c945aa178396910135cc7f93c63'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109360")
def sha1usernamepass(hash, jerar):
    hs='3de3d8093bf04b8eb5f595bc2da3f37358522c9f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109380")
def sha1usernamepasssalt(hash, jerar):
    hs='00025111b3c4d0ac1635558ce2393f77e94770c5'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109400")
def sha1md5pass(hash, jerar):
    hs='fa960056c0dea57de94776d3759fb555a15cae87'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109420")
def sha1md5passsalt(hash, jerar):
    hs='1dad2b71432d83312e61d25aeb627593295bcc9a'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109440")
def sha1md5sha1pass(hash, jerar):
    hs='8bceaeed74c17571c15cdb9494e992db3c263695'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109460")
def sha1sha1pass(hash, jerar):
    hs='3109b810188fcde0900f9907d2ebcaa10277d10e'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109480")
def sha1sha1passsalt(hash, jerar):
    hs='780d43fa11693b61875321b6b54905ee488d7760'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109500")
def sha1sha1passsubstrpass03(hash, jerar):
    hs='5ed6bc680b59c580db4a38df307bd4621759324e'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109520")
def sha1sha1saltpass(hash, jerar):
    hs='70506bac605485b4143ca114cbd4a3580d76a413'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109540")
def sha1sha1sha1pass(hash, jerar):
    hs='3328ee2a3b4bf41805bd6aab8e894a992fa91549'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109560")
def sha1strtolowerusernamepass(hash, jerar):
    hs='79f575543061e158c2da3799f999eb7c95261f07'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("109580")

def Haval192(hash, jerar):
    hs='cd3a90a3bebd3fa6b6797eba5dab8441f16a7dfa96c6e641'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("110040")
def Haval192HMAC(hash, jerar):
    hs='39b4d8ecf70534e2fd86bb04a877d01dbf9387e640366029'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("110080")
def Tiger192(hash, jerar):
    hs='c086184486ec6388ff81ec9f235287270429b2253b248a70'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("110020")
def Tiger192HMAC(hash, jerar):
    hs='8e914bb64353d4d29ab680e693272d0bd38023afa3943a41'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("110060")

def MD5passsaltjoomla1(hash, jerar):
    hs='35d1c0d69a2df62be2df13b087343dc9:BeKMviAfcXeTPTlX'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[32:33].find(':')==0:
        jerar.append("112020")

def SHA1Django(hash, jerar):
    hs='sha1$Zion3R$299c3d65a0dcab1fc38421783d64d0ecf4113448'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:5].find('sha1$')==0:
        jerar.append("113020")

def Haval224(hash, jerar):
    hs='f65d3c0ef6c56f4c74ea884815414c24dbf0195635b550f47eac651a'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("114040")
def Haval224HMAC(hash, jerar):
    hs='f10de2518a9f7aed5cf09b455112114d18487f0c894e349c3c76a681'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("114080")
def SHA224(hash, jerar):
    hs='e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("114020")
def SHA224HMAC(hash, jerar):
    hs='c15ff86a859892b5e95cdfd50af17d05268824a6c9caaa54e4bf1514'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("114060")

def SHA256(hash, jerar):
    hs='2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115020")
def SHA256HMAC(hash, jerar):
    hs='d3dd251b7668b8b6c12e639c681e88f2c9b81105ef41caccb25fcde7673a1132'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115120")
def Haval256(hash, jerar):
    hs='7169ecae19a5cd729f6e9574228b8b3c91699175324e6222dec569d4281d4a4a'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115040")
def Haval256HMAC(hash, jerar):
    hs='6aa856a2cfd349fb4ee781749d2d92a1ba2d38866e337a4a1db907654d4d4d7a'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115140")
def GOSTR341194(hash, jerar):
    hs='ab709d384cce5fda0793becd3da0cb6a926c86a8f3460efb471adddee1c63793'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115060")
def RipeMD256(hash, jerar):
    hs='5fcbe06df20ce8ee16e92542e591bdea706fbdc2442aecbf42c223f4461a12af'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115080")
def RipeMD256HMAC(hash, jerar):
    hs='43227322be1b8d743e004c628e0042184f1288f27c13155412f08beeee0e54bf'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115160")
def SNEFRU256(hash, jerar):
    hs='3a654de48e8d6b669258b2d33fe6fb179356083eed6ff67e27c5ebfa4d9732bb'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115100")
def SNEFRU256HMAC(hash, jerar):
    hs='4e9418436e301a488f675c9508a2d518d8f8f99e966136f2dd7e308b194d74f9'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115180")
def SHA256md5pass(hash, jerar):
    hs='b419557099cfa18a86d1d693e2b3b3e979e7a5aba361d9c4ec585a1a70c7bde4'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115200")
def SHA256sha1pass(hash, jerar):
    hs='afbed6e0c79338dbfe0000efe6b8e74e3b7121fe73c383ae22f5b505cb39c886'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("115220")

def MD5passsaltjoomla2(hash, jerar):
    hs='fb33e01e4f8787dc8beb93dac4107209:fxJUXVjYRafVauT77Cze8XwFrWaeAYB2'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[32:33].find(':')==0:
        jerar.append("116020")
def SAM(hash, jerar):
    hs='4318B176C3D8E3DEAAD3B435B51404EE:B7C899154197E8A2A33121D76A240AB5'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash.islower()==False and hash[32:33].find(':')==0:
        jerar.append("116040")

def SHA256Django(hash, jerar):
    hs='sha256$Zion3R$9e1a08aa28a22dfff722fad7517bae68a55444bb5e2f909d340767cec9acf2c3'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:6].find('sha256')==0:
        jerar.append("117020")

def RipeMD320(hash, jerar):
    hs='b4f7c8993a389eac4f421b9b3b2bfb3a241d05949324a8dab1286069a18de69aaf5ecc3c2009d8ef'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("118020")
def RipeMD320HMAC(hash, jerar):
    hs='244516688f8ad7dd625836c0d0bfc3a888854f7c0161f01de81351f61e98807dcd55b39ffe5d7a78'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("118040")

def SHA384(hash, jerar):
    hs='3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("119020")
def SHA384HMAC(hash, jerar):
    hs='bef0dd791e814d28b4115eb6924a10beb53da47d463171fe8e63f68207521a4171219bb91d0580bca37b0f96fddeeb8b'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("119040")

def SHA256s(hash, jerar):
    hs='$6$g4TpUQzk$OmsZBJFwvy6MwZckPvVYfDnwsgktm2CckOlNJGy9HNwHSuHFvywGIuwkJ6Bjn3kKbB6zoyEjIYNMpHWBNxJ6g.'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:3].find('$6$')==0:
        jerar.append("120020")

def SHA384Django(hash, jerar):
    hs='sha384$Zion3R$88cfd5bc332a4af9f09aa33a1593f24eddc01de00b84395765193c3887f4deac46dc723ac14ddeb4d3a9b958816b7bba'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:6].find('sha384')==0:
        jerar.append("121020")

def SHA512(hash, jerar):
    hs='ea8e6f0935b34e2e6573b89c0856c81b831ef2cadfdee9f44eb9aa0955155ba5e8dd97f85c73f030666846773c91404fb0e12fb38936c56f8cf38a33ac89a24e'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("122020")
def SHA512HMAC(hash, jerar):
    hs='dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("122060")
def Whirlpool(hash, jerar):
    hs='76df96157e632410998ad7f823d82930f79a96578acc8ac5ce1bfc34346cf64b4610aefa8a549da3f0c1da36dad314927cebf8ca6f3fcd0649d363c5a370dddb'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("122040")
def WhirlpoolHMAC(hash, jerar):
    hs='77996016cf6111e97d6ad31484bab1bf7de7b7ee64aebbc243e650a75a2f9256cef104e504d3cf29405888fca5a231fcac85d36cd614b1d52fce850b53ddf7f9'
    if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==True:
        jerar.append("122080")


def identify_hash(h):
    jerar = []

    ADLER32(h, jerar); CRC16(h, jerar); CRC16CCITT(h, jerar); CRC32(h, jerar); CRC32B(h, jerar); DESUnix(h, jerar); DomainCachedCredentials(h, jerar); FCS16(h, jerar); GHash323(h, jerar); GHash325(h, jerar); GOSTR341194(h, jerar); Haval128(h, jerar); Haval128HMAC(h, jerar); Haval160(h, jerar); Haval160HMAC(h, jerar); Haval192(h, jerar); Haval192HMAC(h, jerar); Haval224(h, jerar); Haval224HMAC(h, jerar); Haval256(h, jerar); Haval256HMAC(h, jerar); LineageIIC4(h, jerar); MD2(h, jerar); MD2HMAC(h, jerar); MD4(h, jerar); MD4HMAC(h, jerar); MD5(h, jerar); MD5APR(h, jerar); MD5HMAC(h, jerar); MD5HMACWordpress(h, jerar); MD5phpBB3(h, jerar); MD5Unix(h, jerar); MD5Wordpress(h, jerar); MD5Half(h, jerar); MD5Middle(h, jerar); MD5passsaltjoomla1(h, jerar); MD5passsaltjoomla2(h, jerar); MySQL(h, jerar); MySQL5(h, jerar); MySQL160bit(h, jerar); NTLM(h, jerar); RAdminv2x(h, jerar); RipeMD128(h, jerar); RipeMD128HMAC(h, jerar); RipeMD160(h, jerar); RipeMD160HMAC(h, jerar); RipeMD256(h, jerar); RipeMD256HMAC(h, jerar); RipeMD320(h, jerar); RipeMD320HMAC(h, jerar); SAM(h, jerar); SHA1(h, jerar); SHA1Django(h, jerar); SHA1HMAC(h, jerar); SHA1MaNGOS(h, jerar); SHA1MaNGOS2(h, jerar); SHA224(h, jerar); SHA224HMAC(h, jerar); SHA256(h, jerar); SHA256s(h, jerar); SHA256Django(h, jerar); SHA256HMAC(h, jerar); SHA256md5pass(h, jerar); SHA256sha1pass(h, jerar); SHA384(h, jerar); SHA384Django(h, jerar); SHA384HMAC(h, jerar); SHA512(h, jerar); SHA512HMAC(h, jerar); SNEFRU128(h, jerar); SNEFRU128HMAC(h, jerar); SNEFRU256(h, jerar); SNEFRU256HMAC(h, jerar); Tiger128(h, jerar); Tiger128HMAC(h, jerar); Tiger160(h, jerar); Tiger160HMAC(h, jerar); Tiger192(h, jerar); Tiger192HMAC(h, jerar); Whirlpool(h, jerar); WhirlpoolHMAC(h, jerar); XOR32(h, jerar); md5passsalt(h, jerar); md5saltmd5pass(h, jerar); md5saltpass(h, jerar); md5saltpasssalt(h, jerar); md5saltpassusername(h, jerar); md5saltmd5pass(h, jerar); md5saltmd5passsalt(h, jerar); md5saltmd5passsalt(h, jerar); md5saltmd5saltpass(h, jerar); md5saltmd5md5passsalt(h, jerar); md5username0pass(h, jerar); md5usernameLFpass(h, jerar); md5usernamemd5passsalt(h, jerar); md5md5pass(h, jerar); md5md5passsalt(h, jerar); md5md5passmd5salt(h, jerar); md5md5saltpass(h, jerar); md5md5saltmd5pass(h, jerar); md5md5usernamepasssalt(h, jerar); md5md5md5pass(h, jerar); md5md5md5md5pass(h, jerar); md5md5md5md5md5pass(h, jerar); md5sha1pass(h, jerar); md5sha1md5pass(h, jerar); md5sha1md5sha1pass(h, jerar); md5strtouppermd5pass(h, jerar); sha1passsalt(h, jerar); sha1saltpass(h, jerar); sha1saltmd5pass(h, jerar); sha1saltmd5passsalt(h, jerar); sha1saltsha1pass(h, jerar); sha1saltsha1saltsha1pass(h, jerar); sha1usernamepass(h, jerar); sha1usernamepasssalt(h, jerar); sha1md5pass(h, jerar); sha1md5passsalt(h, jerar); sha1md5sha1pass(h, jerar); sha1sha1pass(h, jerar); sha1sha1passsalt(h, jerar); sha1sha1passsubstrpass03(h, jerar); sha1sha1saltpass(h, jerar); sha1sha1sha1pass(h, jerar); sha1strtolowerusernamepass(h, jerar)

    if len(jerar)==0:

        print("\n Not Found.")
    elif len(jerar)>2:
        jerar.sort()
        print("\nPossible Hashs:")
        print("[+] "+str(algorithms[jerar[0]]))
        print("[+] "+str(algorithms[jerar[1]]))
        print("\nLeast Possible Hashs:")
        for a in range(int(len(jerar))-2):
            print("[+] "+str(algorithms[jerar[a+2]]))
    else:
        jerar.sort()
        print("\nPossible Hashs:")
        for a in range(len(jerar)):
            print("[+] "+str(algorithms[jerar[a]]))

    return jerar

def try_john(h, jerar):
    print("")
    priority_list = []
    for i in jerar:
        algos = john_relations[i]
        for algo in algos:
            if algo not in priority_list:
                priority_list.append(algo)
    
    if len(priority_list) > 0:
        hashfile = open("passfile", 'w')
        hashfile.write(h)
        hashfile.close()

        for algorithm in priority_list:
            print(f"\nTrying {algorithm}...")
            result = subprocess.run(['john', f"--format={algorithm}", "--wordlist=/usr/share/wordlists/rockyou.txt", "passfile"], stdout = subprocess.PIPE).stdout.decode('utf-8')
            if "No password hashes loaded" not in result:
                if "No password hashes left to crack" in result:
                    user = os.getenv("USER")
                    pot = open(f"/home/{user}/.john/john.pot", "r").read()
                    pattern = re.compile(".*" + h + ".*")

                    print("\n***** Hash already cracked as " + algorithm + ". *****")
                    print("\ncracked string: " + pattern.search(pot).group(0).strip().split(":")[-1] + "\n")
                    print("***** Check '~/.john/john.pot' for more info *****")
                    exit(0)
                else:
                    print(result + "\n")
                if "(?)" in result:
                    exit(0)

def main():
    print(logo)
    try:
        first = str(argv[1])
    except:
        first = None

    try:
        print("-"*50)
        if first:
            h = first
        else:
            h = input(" HASH: ")

        jerar = identify_hash(h)

        if len(jerar) > 0:
            try_john(h, jerar)

    except KeyboardInterrupt:
        print("\n\n\tBye!")
        exit()

if __name__ == "__main__":
    main()
