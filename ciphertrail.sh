#!/bin/bash
# CipherTrail
# Educational Bash encoder/decoder tool with protected key-file handling
# Author: Andrew Edwards 
# Purpose: Cybersecurity scripting and encoding/decoding practice lab for students and professionals. Demonstrates encoding, obfuscation, and key file protection concepts.

set -euo pipefail
IFS=$'\n\t'

RESULTS_DIR="$HOME/encoder_results"
mkdir -p "$RESULTS_DIR"

# Create a unique job name based on timestamp to avoid overwriting results
timestamp=$(date +"%Y%m%d_%H%M%S")
job_name="job_${timestamp}"

# Version information and script name for help and logging
VERSION="1.1.0"
SCRIPT_NAME="$(basename "$0")"

# Default behavior flags (can be overridden by CLI options)

INTERACTIVE=true
VERBOSE=false
TRACE=false
QUIET=false
SELF_TEST=false
DRY_RUN=false

# CLI-controlled values

mode=""
input_mode=""
input_text=""
infile=""
output_file=""
key_file=""
iterations=""
max_rotation=""
key_password=""
password_env_var=""
show_output="n"

# Default settings for encoding parameters

DEFAULT_ITERATIONS=3
DEFAULT_MAX_ROTATION=8
MAX_ITERATIONS=25

# -----------------
# Helper functions
# -----------------

# Standard output and error helpers with verbosity control

die() {
	echo "ERROR: $*" >&2
	exit 1
}

log() {
	if [[ "$QUIET" != true ]]; then
		echo "$*"
	fi
}

verbose_log() {
	if [[ "$VERBOSE" == true || "$TRACE" == true ]]; then
		echo "[info] $*" >&2
	fi
}

trace_log() {
	if [[ "$TRACE" == true ]]; then
		echo "[trace] $*" >&2
	fi
}

# Help menu and educational explanation

print_usage() {
  cat <<EOF
CipherTrail v$VERSION

Educational command-line encoding and transformation lab.

Usage:
	$SCRIPT_NAME
	$SCRIPT_NAME encode [options]
	$SCRIPT_NAME decode [options]
	$SCRIPT_NAME explain
	$SCRIPT_NAME clean [options]
	$SCRIPT_NAME --self-test
	$SCRIPT_NAME --help
	$SCRIPT_NAME --version

Encode options:
    -i, --input FILE                Read input from a file
        --text TEXT                 Use direct text input
    -o, --output FILE               Payload output file
    -k, --key FILE                  Key output file
    -n, --iterations NUM            Number of encoding layers, max $MAX_ITERATIONS
    -r, --max-rotations NUM         Maximum rotation amount
        --passwords-env VAR         Read key password from environment variable

Decode options:
    -i, --input FILE                Encoded payload file
        --text TEXT                 Encoded payload text
    -k, --key FILE                  Protected key file
    -o, --output FILE               Decoded output file
        --show                      Display decoded output in terminal
        --password-env VAR.         Read key password from environment variable
	
Output options:
        --verbose                   Show high-level process messages
        --trace                     Show each transformation step
        --quiet                     Suppress normal output

Educational options:
        explain                     Explain encoding, obfuscation, and key files
        --self-test                 Run a built-in encode/decode verification test

Examples:
	$SCRIPT_NAME encode --input examples/sample_input.txt --iterations 5 --max-rotation 8 --verbose
	$SCRIPT_NAME decode --input payload.txt --key key.txt --show
	CIPHERTRAIL_PASSWORD='testpass' $SCRIPT_NAME encode --input message.txt --password-env CIPHERTRAIL_PASSWORD
EOF
}

# Explain mode

print_explain() {
  cat <<'EOF'
CipherTrail Educational Explanation

CipherTrail demonstrates the difference between encoding, obfuscation, and encryption.

1. Base64 encoding
   Base64 changes data into a text-safe format. It is reversible and not encryption.

2. String rotation
   Rotation moves characters from one side of the string to the other. It is reversible obfuscation.

3. String reversal
   Reversal flips the order of characters. It is also reversible obfuscation.

4. Protected key file
   CipherTrail records the operations needed to reverse the payload. That operation recipe is protected with a password using OpenSSL.

5. Integrity checking
   CipherTrail uses SHA-256 to verify that the decrypted key instructions have not been changed.

Important:
CipherTrail is an educational security tool. It should not be used as production encryption.
EOF
}

# Command-Line argument parsing with support for interactive mode, direct input, file input, and various options

parse_args() {
	if [[ "$#" -eq 0 ]]; then
		INTERACTIVE=true
		return 0
	fi

	INTERACTIVE=false

	case "$1" in
		encode|e)
			mode="e"
			shift
			;;
		decode|d)
			mode="d"
			shift
			;;
		explain)
			print_explain
			exit 0
			;;
		clean)
	   		mode="clean"
			shift
			;;
		--self-test)
			SELF_TEST=true
			shift
			;;
		-h|--help)
			print_usage
			exit 0
			;;
		--version)
			echo "CipherTrail v$VERSION"
			exit 0
			;;
		*)
			die "Unknown command: $1. Use --help for usage."
			;;
	esac

	while [[ "$#" -gt 0 ]]; do
		case "$1" in
			-i|--input)
				[[ "${2:-}" ]] || die "Missing value for $1"
				infile="$2"
				input_mode="f"
				shift 2
				;;
			--text)
				[[ "${2:-}" ]] || die "Missing value for --text"
				input_text="$2"
				input_mode="i"
				shift 2
				;;
			-o|--output)
				[[ "${2:-}" ]] || die "Missing value for $1"
				output_file="$2"
				shift 2
				;;
			-k|--key)
				[[ "${2:-}" ]] || die "Missing value for $1"
				key_file="$2"
				shift 2
				;;
			-n|--iterations)
				[[ "${2:-}" ]] || die "Missing value for $1"
				iterations="$2"
				shift 2
				;;
			-r|--max-rotation)
				[[ "${2:-}" ]] || die "Missing value for $1"
				max_rotation="$2"
				shift 2
				;;
			--password-env)
				[[ "${2:-}" ]] || die "Missing value for --password-env"
				password_env_var="$2"
				shift 2
				;;
			--show)
				show_output="y"
				shift
				;;
			--verbose)
				VERBOSE=true
				shift
				;;
			--trace)
				TRACE=true
				VERBOSE=true
				shift
				;;
			--quiet)
				QUIET=true
				shift
				;;
			*)
				die "Unknown option: $1. Use --help for usage."
				;;
		esac
	done
}

# Password handling with optional environment variable support for non-interactive use in scripts or CI environments

get_password_from_env() {
	if [[ -n "$password_env_var" ]]; then
		local value="${!password_env_var-}"
		[[ -n "$value" ]] || die "Environment variable '$password_env_var' is empty or not set."
		printf "%s" "$value"
		return 0
	fi

	return 1
}

prompt_for_new_password() {
	local password=""
	local confirm=""

	if password=$(get_password_from_env); then
	printf "%s" "$password"
	return 0
	fi

	read -r -s -p "Create a password to protect the key file: " password
	echo 
	read -r -s -p $'\nConfirm the password: ' confirm
	echo

	[[ -n "$password" ]] || die "Password cannot be empty!"
	[[ "$password" == "$confirm" ]] || die "Passwords do not match!"

	printf "%s" "$password"
}

prompt_for_existing_password() {
	local password=""

	if password=$(get_password_from_env); then
		printf "%s" "$password"
		return 0
	fi

	read -r -s -p $'Enter the password for the key file: \n' password
	echo

	[[ -n "$password" ]] || die "Password cannot be empty!"

	printf "%s" "$password"
}

# Add input loading with support for direct text input or file input, and path resolution for files in the results directory or absolute paths

load_input_value() {
	if [[ "$input_mode" == "i" ]]; then
		if [[ -z "$input_text" ]]; then
			read -r -p "Hello, please enter your string: " input_text
		fi

		[[ -n "$input_text" ]] || die "Input cannot be empty."
		printf "%s" "$input_text"
		return 0
	fi

	if [[ "$input_mode" == "f" ]]; then
		if [[ -z "$infile" ]]; then
			read -r -p "Enter the input file name: " infile
		fi

		infile=$(resolve_path "$infile")
		[[ -n "$infile" && -f "$infile" ]] || die "Input file not found."

		local data
		data=$(<"$infile")
		[[ -n "$data" ]] || die "Input file is empty."

		printf "%s" "$data"
		return 0
	fi

	read -r -p "Would you like to use direct input or read from a file? (i/f): " input_mode

	case "$input_mode" in
		i|f)
			load_input_value
			;;
		*)
			die "Invalid input mode. Use 'i' for direct input, or 'f' for file."
			;;
	esac
}

# Validation helpers for numeric parameters with range checks

validate_positive_integer() {
	local value="$1"
	local label="$2"

	[[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$label must be a positive integer."
}

validate_iterations() {
	validate_positive_integer "$iterations" "Iterations"

	if [[ "$iterations" -gt "$MAX_ITERATIONS" ]]; then
		die "Max iterations is $MAX_ITERATIONS."
	fi
}

validate_max_rotation() {
	validate_positive_integer "$max_rotation" "Max rotation"
}

# Self-test function to verify that encoding and decoding processes work correctly with a known input and transformations, using temporary files for isolation

run_self_test() {
	log "Running CipherTrail self-test..."

	local original="CipherTrail self-test message"
	local password="CipherTrailSelfTestPassword123!"
	local temp_dir
	temp_dir=$(mktemp -d)

	local test_payload="$temp_dir/payload.txt"
	local test_key="$temp_dir/key.txt"
	local test_decoded="$temp_dir/decoded.txt"

	local saved_results_dir="$RESULTS_DIR"
	RESULTS_DIR="$temp_dir"

	local var="$original"
	local test_iterations=3
	local test_max_rotation=5
	local plain_key_data=""
	local counter rotation strlen

	plain_key_data+="# paired with $(basename "$test_payload")"$'\n'
	plain_key_data+="# format: iteration|operation|amount"$'\n'

	for ((counter=1; counter<=test_iterations; counter++)); do
		var=$(encode_base64 "$var")

		if (( counter % 2 ==1 )); then
			strlen=${#var}
			if [[ "$strlen" -le 1 ]]; then
				rotation=0
			else
				rotation=$(( (RANDOM % test_max_rotation) + 1 ))
				rotation=$(( rotation % strlen ))
				[[ "$rotation" -eq 0 ]] && rotation=1
			fi

			var=$(rotate_left "$var" "$rotation")
			plain_key_data+="${counter}|rotate|${rotation}"$'\n'
		else
			var=$(reverse_string "$var")
			plain_key_data+="${counter}|reverse|0"$'\n'
		fi
	done

	plain_key_data="${plain_key_data%$'\n'}"

	printf "%s" "$var" > "$test_payload"
	write_protected_keyfile "$plain_key_data" "$test_key" "$password"

	local encoded_payload
	encoded_payload=$(<"$test_payload")

	local recovered_key_data
	recovered_key_data=$(read_protected_keyfile "$test_key" "$password")

	local key_lines=()
	while IFS= read -r line; do
		key_lines+=("$line")
	done < <(printf "%s\n" "$recovered_key_data" | grep -E '^[0-9]+\|(rotate|reverse)\|[0-9]+$')

	var="$encoded_payload"

	local idx iteration operation amount decoded
	for ((idx=${#key_lines[@]}-1; idx>=0; idx--)); do
		IFS='|' read -r iteration operation amount <<< "${key_lines[idx]}"

		if [[ "$operation" == "rotate" ]]; then
			var=$(rotate_right "$var" "$amount")
		elif [[ "$operation" == "reverse" ]]; then
			var=$(reverse_string "$var")
		else
			die "Self-test failed: Invalid operation."
		fi

		decoded=$(decode_base64 "$var") || die "Self-test failed during Base64 decode."
		var="$decoded"
	done

	printf "%s" "$var" > "$test_decoded"

	if [[ "$var" == "$original" ]]; then
		log "Self-test passed."
	else
		die "Self-test failed: Decoded output does not match original input."
	fi

	RESULTS_DIR="$saved_results_dir"
	rm -rf "$temp_dir"
}

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

# Wrap plain key data into protected file format with hash and encrypted payload

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

# ---------------------------------------------------------------------------------------------
# Check dependencies before proceeding with the main logic, and run self-test if requested
# ---------------------------------------------------------------------------------------------

parse_args "$@"

check_dependencies || exit 1

if [[ "$SELF_TEST" == true ]]; then
	run_self_test
	exit 0
fi

if [[ -z "$mode" ]]; then
	read -r -p "Would you like to encode or decode? (e/d): " mode
fi

if [[ "$mode" != "e" && "$mode" != "d" && "$mode" != "clean" ]]; then
	die "Invalid mode! Use 'e' for encode, 'd' for decode, or --help for usage."
fi

if [[ "$mode" == "clean" ]]; then
	log "Clean mode will be added in Version 1.3."
	exit 0
fi

var=$(load_input_value)

# -------------
# Encode mode
# -------------

if [ "$mode" = "e" ]; then
		if [[ -z "$iterations" ]]; then
			read -r -p "How many times would you like this encoded? (MAX $MAX_ITERATIONS): " iterations
		fi

		validate_iterations

		if ! [[ "$iterations" =~ ^[1-9][0-9]*$ ]]; then
				echo "Must be a positive integer from 1-25!"
				exit 1
		fi

		if [ "$iterations" -gt 25 ]; then
				echo "Max iterations is 25!"
				exit 1
		fi

		if [[ -z "$max_rotation" ]]; then
			read -r -p "Enter maximum random rotation amount for odd iteration: " max_rotation
		fi

		validate_max_rotation

		if ! [[ "$max_rotation" =~ ^[1-9][0-9]*$ ]]; then
				echo "Max rotation must be a positive integer!"
				exit 1
		fi

		key_password=$(prompt_for_new_password)

		if [ -z "$key_password" ]; then
				echo "Password cannot be empty!"
				exit 1
		fi


		if [[ -z "$output_file" ]]; then
			output_file="$RESULTS_DIR/${job_name}_payload.txt"
		fi

		if [[ -z "$key_file" ]]; then
			key_file="$RESULTS_DIR/${job_name}_key.txt"
		fi

        plain_key_data=""
        plain_key_data+="# paired with $(basename "$output_file")"$'\n'
        plain_key_data+="# format: iteration|operation|amount"$'\n'

		for ((counter=1; counter<=iterations; counter++))
		do
				var=$(encode_base64 "$var")

				trace_log "Iteration $counter: Applied Base64 encoding."

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

						trace_log "Iteration $counter: Applied rotate-left by $rotation."
				else
						var=$(reverse_string "$var")
						plain_key_data+="${counter}|reverse|0"$'\n'

						trace_log "Iteration $counter: Applied string reversal."
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

		log ""
		log "Encoding complete"
		log "Payload saved to: $output_file"
		log "Encrypted key saved to: $key_file"
fi

# ------------
# Decode mode
# ------------

if [ "$mode" = "d" ]; then
		if [[ -z "$key_file" ]]; then
			echo
			echo "Tip: payload and key files are usually paired like:"
			echo " job_YYYYMMDD_HHMMSS_payload.txt"
			echo " job_YYYYMMDD_HHMMSS_key.txt"
			echo
			echo "Available files in $RESULTS_DIR:"
			ls -1 "$RESULTS_DIR" 2>/dev/null || true
			echo

			read -r -p "Enter the encrypted key file name: " key_file
		fi

		key_file=$(resolve_path "$key_file")
		[[ -n "$key_file" && -f "$key_file" ]] || die "Key file not found"

		key_password=$(prompt_for_existing_password)

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

				trace_log "Replaying iteration $iteration in reverse: $operation $amount"
		done

		if [[ "$show_output" != "y" && "$INTERACTIVE" == true ]]; then
			read -r -p $'\nDisplay decoded output in terminal? (y/n): ' show_output
		fi

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