# Hash Identifier

This project is based on original code by blacksplit @ https://github.com/blackploit/hash-identifier
all credit for hash identification algorithm goes to them.

Identify hash type and use John the ripper to attempt to crack it.

This script will first identify the type of hash and then enumerate the possible hashes that jonn the ripper supports which may match.
It then passes the hash to john the ripper once for each matching format and presents the results until it is either cracked or john 
says that there are no more hashes left to crack.
