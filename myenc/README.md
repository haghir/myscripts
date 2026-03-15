# myenc

## Encryption

This command encrypts the specified file with the passphrase.

**Usage:**

``` shell
python3 -m myenc -f <input file> -o <output file> -p <passphrase> -s <password salt> -h <password hash>
```

- `-f`: Input file path to be encrypted
- `-o`: Output file path (optional)
- `-p`: Passphrase (optional)
- `-s`: Salt used to check the passphrase
- `-h`: SHA256 hash used to check the passphrase

**Encryption Process:**

1. If `-p` is not specified, prompt for the passphrase
2. Calculate an SHA256 value of the salt + passphrase
3. Check if the calculated hash value equals the specified hash value
4. If the above hash values was not matched, abort the process
5. Encrypt the input file by AES256-GCM and encode in base64 string
6. Output to the specified file (If not specified, output to the stdout)
