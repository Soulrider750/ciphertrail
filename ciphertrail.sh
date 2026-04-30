#!/bin/bash
# CipherTrail
# Educational Bash encoder/decoder tool with protected key-file handling.
# Author: Andrew Edwards
# Purpose: Cybersecrity scripting and encoding/decoding practice.

set -euo pipefail
IFS=$'\n\t'

RESULTS_DIR="$HOME/encoder_results"
mkdir -p "$RESULTS_DIR"

timestamp=$(date +"%Y%m%d_%H%M%S")
job_name="job_${timestamp}"

# -----------------
# Helper functions
# -----------------

resolve_path() {
    local input="$1"

    if [[ "$input" == ~* ]]; then
        input="${input/#\~/$HOME}"
    fi

    if [[ "$input" = /* ]]; then
        if [[ -f "$input" ]]; then
            echo "$input"
        else
            echo ""
        fi
        return
    fi

    if [[ -f "$RESULTS_DIR/$input" ]]; then
        echo "$RESULTS_DIR/$input"
        return
    fi

    if [[ -f "$input" ]]; then
        echo "$input"
        return
    fi

    echo ""
}

reverse_string() {
	local str="$1"
	local rev=""
	local i

	for (( i=${#str}-1; i>=0; i-- )); do
		rev+="${str:i:1}"
	done

	printf "%s" "$rev"
}

rotate_left() {
		local str="$1"
		local n="$2"
		local len=${#str}

		if [ "$len" -eq 0 ]; then
				printf "%s" "$str"
				return
		fi

		n=$((n % len))
		printf "%s" "${str:n}${str:0:n}"
}

rotate_right() {
		local str="$1"
		local n="$2"
		local len=${#str}

		if [ "$len" -eq 0 ]; then
				printf "%s" "$str"
				return
		fi

		n=$((n % len))
		printf "%s" "${str:len-n}${str:0:len-n}"
}

encode_base64() {
		printf "%s" "$1" | base64 | tr -d '\n'
}

decode_base64() {
		local input="$1"
		local decoded

		decoded=$(printf "%s" "$input" | base64 -d 2>/dev/null) && {
				printf "%s" "$decoded"
				return 0
		}

		decoded=$(printf "%s" "$input" | base64 --decode 2>/dev/null) && {
				printf "%s" "$decoded"
				return 0
		}

		decoded=$(printf "%s" "$input" | base64 -D 2>/dev/null) && {
				printf "%s" "$decoded"
				return 0
		}

		return 1
}

sha256_string() {
		local data="$1"

		if command -v sha256sum >/dev/null 2>&1; then
				printf "%s" "$data" | sha256sum | awk '{print $1}'
				return 0
		fi

		if command -v shasum >/dev/null 2>&1; then
				printf "%s" "$data" | shasum -a 256 | awk '{print $1}'
				return 0
		fi

		echo "No SHA-256 tool found (need sha256sum or shasum)." >&2
		return 1
}

check_openssl() {
		if ! command -v openssl >/dev/null 2>&1; then
				echo "OpenSSL is required but not installed." >&2
				return 1
		fi
		return 0
}

check_hash_tool() {
    if command -v sha256sum >/dev/null 2>&1; then
        return 0
    fi
    if command -v shasum >/dev/null 2>&1; then
        return 0
    fi
    echo "No SHA-256 tool found (need sha256sum or shasum)." >&2
    return 1
}

check_base64_tool() {
    if command -v base64 >/dev/null 2>&1; then
        return 0
    fi
    echo "Base64 encoding/decoding requires the base64 command." >&2
    return 1
}

check_dependencies() {
    check_openssl || return 1
    check_hash_tool || return 1
    check_base64_tool || return 1
    return 0
}

encrypt_with_password() {
	local plaintext="$1"
	local password="$2"
	local err_file 

	err_file=$(mktemp) || return 1

	if ! output=$(printf "%s" "$plaintext" | \
		openssl enc -aes-256-cbc -pbkdf2 -salt -a -A -pass fd:3 3<<<"$password" 2>"$err_file"); then
		echo "ERROR: OpenSSL encryption failed" >&2
		cat "$err_file" >&2
		rm -f "$err_file"
		return 1
	fi

	rm -f "$err_file"
	printf "%s" "$output"
}

decrypt_with_password() {
	local ciphertext="$1"
	local password="$2"
	local err_file

	err_file=$(mktemp) || return 1

	if ! output=$(printf "%s" "$ciphertext" | \
		openssl enc -aes-256-cbc -pbkdf2 -d -a -A -pass fd:3 3<<<"$password" 2>"$err_file"); then
		echo "ERROR: OpenSSL decryption failed" >&2
		cat "$err_file" >&2
		rm -f "$err_file"
		return 1
	fi

	rm -f "$err_file"
	printf "%s" "$output"
}

# Wrap plain key data into protected file format
write_protected_keyfile() {
		local plain_key_data="$1"
		local key_file="$2"
		local password="$3"

		local key_hash
		local encrypted_payload

        key_hash=$(sha256_string "$plain_key_data")
        if [ $? -ne 0 ] || [ -z "$key_hash" ]; then
            echo "Failed to generate key hash." >&2
            return 1
        fi

        encrypted_payload=$(encrypt_with_password "$plain_key_data" "$password")
        if [ $? -ne 0 ] || [ -z "$encrypted_payload" ]; then
            echo "Failed to encrypt key payload." >&2
            return 1
        fi

		{
				echo "# encoder key file"
				echo "FORMAT_VERSION=2"
				echo "PROTECTION=OPENSSL_AES_256_CBC_PBKDF2"
				echo "HASH_ALGO=SHA256"
				echo "HASH=$key_hash"
				echo "PAYLOAD=$encrypted_payload"
		} > "$key_file" || {
				echo "Failed to write key file!" >&2
				return 1
		}
}

# Read protected key file, decrypt payload, verify hash, output plain key data
read_protected_keyfile() {
		local key_file="$1"
		local password="$2"

		if [ ! -f "$key_file" ]; then
				echo "Key file not found!" >&2
				return 1
		fi

		local stored_hash
		local payload
		local decrypted_payload
		local computed_hash

		stored_hash=$(grep '^HASH=' "$key_file" | head -n1 | cut -d'=' -f2-)
		payload=$(grep '^PAYLOAD=' "$key_file" | head -n1| cut -d'=' -f2-)

		if [ -z "$stored_hash" ] || [ -z "$payload" ]; then
				echo "Key file is missing HASH or PAYLOAD fields!" >&2
				return 1
		fi

		decrypted_payload=$(decrypt_with_password "$payload" "$password")
		if [ $? -ne 0 ] || [ -z "$decrypted_payload" ]; then
				echo "Failed to decrypt key payload. Check the password and make sure the key file was not modified." >&2
				return 1
		fi

		computed_hash=$(sha256_string "$decrypted_payload") || return 1

		if [ "$stored_hash" != "$computed_hash" ]; then
				echo "Key file integrity check failed! Hash mismatch." >&2
				return 1
		fi

		printf "%s" "$decrypted_payload"
}

# --------------------
# Check dependencies
# --------------------

check_dependencies || exit 1

# -------------------------------------
# Ask user whether to encode or decode
# -------------------------------------

read -r -p "Would you like to encode or decode? (e/d): " mode

if [[ "$mode" != "e" && "$mode" != "d" ]]; then
		echo "Invalid mode! Use 'e' for encode or 'd' for decode."
		exit 1
fi

# -----------------------------------------------
# Ask user whether to use direct input or a file
# -----------------------------------------------

read -r -p "Would you like to use direct input or read from a file? (i/f): " input_mode

if [ "$input_mode" = "i" ]; then
		read -r -p "Hello, please enter your string: " var
        if [ -z "$var" ]; then
                echo "Input cannot be empty!"
                exit 1
        fi
elif [ "$input_mode" = "f" ]; then
		read -r -p "Enter the input file name: " infile
        infile=$(resolve_path "$infile")

        if [ -z "$infile" ] || [ ! -f "$infile" ]; then
                echo "Input file not found!"
                exit 1
        fi

		var=$(<"$infile")

        if [ -z "$var" ]; then
                echo "Input file is empty!"
                exit 1
        fi 
else
		echo "Invalid input mode! use 'i' for direct input or 'f' for file."
		exit 1
fi

# -------------
# Encode mode
# -------------

if [ "$mode" = "e" ]; then
		read -r -p "How many times would you like this encoded? (MAX 25): " iterations

		if ! [[ "$iterations" =~ ^[1-9][0-9]*$ ]]; then
				echo "Must be a positive integer from 1-25!"
				exit 1
		fi

		if [ "$iterations" -gt 25 ]; then
				echo "Max iterations is 25!"
				exit 1
		fi

		read -r -p "Enter maximum random rotation amount for odd iterations: " max_rotation

		if ! [[ "$max_rotation" =~ ^[1-9][0-9]*$ ]]; then
				echo "Max rotation must be a positive integer!"
				exit 1
		fi

		read -r -s -p "Create a password to protect the key file: " key_password
		echo
		read -r -s -p "Confirm the password: " key_password_confirm
		echo

		if [ -z "$key_password" ]; then
				echo "Password cannot be empty!"
				exit 1
		fi

		if [ "$key_password" != "$key_password_confirm" ]; then
				echo "Passwords do not match!"
				exit 1
		fi

		output_file="$RESULTS_DIR/${job_name}_payload.txt"
		key_file="$RESULTS_DIR/${job_name}_key.txt"

        plain_key_data=""
        plain_key_data+="# paired with $(basename "$output_file")"$'\n'
        plain_key_data+="# format: iteration|operation|amount"$'\n'

		for ((counter=1; counter<=iterations; counter++))
		do
				var=$(encode_base64 "$var")

				if (( counter % 2 == 1 )); then
						strlen=${#var}

						if [ "$strlen" -le 1 ]; then
								rotation=0
						else
								rotation=$(( (RANDOM % max_rotation) + 1 ))
								rotation=$(( rotation % strlen ))

								if [ "$rotation" -eq 0 ]; then
										rotation=1
								fi
						fi

						var=$(rotate_left "$var" "$rotation")
						plain_key_data+="${counter}|rotate|${rotation}"$'\n'
				else
						var=$(reverse_string "$var")
						plain_key_data+="${counter}|reverse|0"$'\n'
				fi
		done

		plain_key_data="${plain_key_data%$'\n'}"

        mkdir -p "$(dirname "$output_file")"
		printf "%s" "$var" >"$output_file"

        mkdir -p "$(dirname "$key_file")"
		write_protected_keyfile "$plain_key_data" "$key_file" "$key_password"
		if [ $? -ne 0 ]; then
				echo "Failed to write encrypted key file. See the error above for details." >&2
				exit 1
		fi

		echo
		echo "Encoding complete."
		echo "Payload saved to: $output_file"
		echo "Encrypted key saved to: $key_file"
		exit 0
fi

# ------------
# Decode mode
# ------------

if [ "$mode" = "d" ]; then
		echo
		echo "Tip: payload and key files are usually paired like:"
		echo "  job_YYYYMMDD_HHMMSS_payload.txt"
		echo "  job_YYYYMMDD_HHMMSS_key.txt"
		
		echo
		echo "Available files in $RESULTS_DIR:"
		ls -1 "$RESULTS_DIR"
		echo

		read -r -p "Enter the encrypted key file name: " key_file
        key_file=$(resolve_path "$key_file")

        if [ -z "$key_file" ] || [ ! -f "$key_file" ]; then
                echo "Key file not found!"
                exit 1
        fi

		read -r -s -p "Enter the password for the key file: " key_password
		echo

		plain_key_data=$(read_protected_keyfile "$key_file" "$key_password")
		if [ $? -ne 0 ]; then
				exit 1
		fi

		key_base=$(basename "$key_file")
		if [[ "$key_base" == *_key.txt ]]; then
				job_base="${key_base%_key.txt}"
		else
				job_base="decoded_${timestamp}"
		fi

		output_file="$RESULTS_DIR/${job_base}_decoded.txt"

		key_lines=()
		while IFS= read -r line; do
			key_lines+=("$line")
		done < <(printf "%s\n" "$plain_key_data" | grep -E '^[0-9]+\|(rotate|reverse)\|[0-9]+$')

		if [ "${#key_lines[@]}" -eq 0 ]; then
				echo "Protected key file does not contain valid operation lines!"
				exit 1
		fi

# Replay the operations in reverse order to decode the payload
		for ((idx=${#key_lines[@]}-1; idx>=0; idx--))
		do
				IFS='|' read -r iteration operation amount <<< "${key_lines[idx]}"

				if [ "$operation" = "rotate" ]; then
						var=$(rotate_right "$var" "$amount")
				elif [ "$operation" = "reverse" ]; then
						var=$(reverse_string "$var")
				else
						echo "Invalid operation in the key data!"
						exit 1
				fi

				decoded=$(decode_base64 "$var")
				if [ $? -ne 0 ]; then
						echo "Decoding failed while replaying iteration $iteration!"
						exit 1
				fi

				var="$decoded"
		done

		read -r -p "Display decoded output in terminal? (y/n): " show_output

		mkdir -p "$(dirname "$output_file")"
		printf "%s" "$var" > "$output_file"

		echo
		echo "Decoding complete."

		if [[ "$show_output" == "y" ]]; then
			echo
			echo "----- DECODED OUTPUT -----"
			printf "%s\n" "$var"
			echo "--------------------------"
		fi

		echo
		echo "Decoded output saved to: $output_file"
		echo "Verified encrypted key file used: $key_file"
fi
