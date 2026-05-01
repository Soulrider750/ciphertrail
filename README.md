# CipherTrail

CipherTrail is an educational Bash-based encoder and decoder tool used for cybersecurity scripting practice. It allows a user to encode direct input or file input through layered Base64 encoding, randomized string rotation, and string reversal operations. The tool also creates a paired protected key file that stores the decoding steps needed to reverse the process.

## Purpose

This project was created as a cybersecurity learning project to practice Bash scripting, command-line tool design, file handling, input validation, encoding/decoding workflow, OpenSSL usage, password-protected key files, and SHA-256 integrity checking.

CipherTrail is not intended to replace modern encryption tools or production-grade cryptographic software. Instead, it is a portfolio project meant to demonstrate scripting ability, security awareness, and understanding of how encoding, transformation logic, password protection, and integrity verification can work together in a command-line workflow.

## Features

- Encode direct user input or file input.
- Decode previously encoded payloads.
- Save encoded payloads to an output file. 
- Generate a paired protected key file.
- Protect key file contents using OpenSSL AES-256-CBC with PBKDF2
- Verify protected key file integrity using SHA-256.
- Apply layered Base64 encoding.
- Apply randomized left rotation on odd-numbered iterations.
- Apply string reversal on even-numbered iterations.
- Replay operations in reverse order during decoding.
- Support macOS and Linux environments
- Store generated output files in a dedicated results directory.

## Important Security Note

CipherTrail is an educational encoding and obfuscation tool. While the key file is protected using OpenSSL and checked with SHA-256 integrity verification, the project should not be treated as a replacement for modern encryption standards, secure file encryption tools, or a professionally reviewed cryptographic software.

For real-world encryption needs, use established tools and libraries that are actively maintained, peer reviewed, and designed for production security.

## How It Works

During encoding, CipherTrail repeatedly applies Base64 encoding to the input. On odd-numbered iterations, it also applies a randomized left rotation. On even-numbered iterations, it reverses the string. The tool records each transformation step in a key file.

The key file is then protected with a user-created password. During decoding, CipherTrail decrypts the protected key file, verifies its SHA-256 hash, reads the stored transformation steps, and reverses the operations in the correct order to recover the original input.

## Requirements

CipherTrail requires the following tools:

- Bash
- OpenSSL
- Base64
- sha256sum or shasum

On macOS, `shasum` is usually available by default. On many Linux systems, `sha256sum` is usually available by default.

## Installation

Clone the repository:

```bash
git clone https://github.com/Soulrider750/ciphertrail.git
cd ciphertrail
```

Make the script executable:

```bash
chmod +x ciphertrail.sh
```

## Usage

Run the script:

```bash
./ciphertrail.sh
```

CipherTrail will ask whether you want to encode or decode:

```bash
Would you like to encode or decode? (e/d):
```

It will then ask whether you want to use direct input or read from a file:

```bash
Would you like to use direct input or read from a file? (i/f):
```

## Encoding Example

Run:

```bash
./ciphertrail.sh
```

Choose:

```bash
e
```

Then choose either direct input or file input.

The tool will ask how many times you want to encode the input, the maximum random rotation amount, and the password used to protect the key file.

After encoding, CipherTrail saves two files:

```bash
job_YYYYMMDD_HHMMSS_payload.txt
job_YYYYMMDD_HHMMSS_key.txt
```

The payload file contains the encoded input. The key file contains the protected decoding instructions.

## Decoding example

Run:

```bash
./ciphertrail.sh
```

Choose:

```bash
d
```

Select the encoded payload input, then provide the matching key file and password.

If the password is correct and the key file passes the SHA-256 integrity check, CipherTrail reverses the recorded operations and saves the decoded output.

## Example File

A sample input file is included in the `examples/` folder:

```bash
examples/sample_input.txt
```

You can use this file to test CipherTrail without creating your own input file first.

## Project Structure

```bash
ciphertrail/
├── ciphertrail.sh
├── README.md
├── LICENSE
├── .gitignore
└── examples/
    └── sample_input.txt
```

## Skills Demonstrated

This project demonstrates:

- Bash scripting
- Command-line tool development
- File input and output handling
- User input validation
- Encoding and decoding logic
- OpenSSL command-line usage
- Password-protected key-file handling
- SHA-256 integrity checking
- macOS/Linux compatibility considerations
- Cybersecurity-focused documentation

## Disclaimer

CipherTrail is for educational and portfolio use only. Do not use this tool to protect sensitive production data. The project is designed to demonstrate scripting, encoding workflows, and security concepts in a beginner-to-intermediate cybersecurity context.

## Author

Andrew Edwards

```text
Soulrider750
```
