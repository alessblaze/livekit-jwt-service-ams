#!/bin/bash
# Ed25519 Key Generator and Base64 Encoder for MatrixRTC Authorization Service

set -e

generate_keypair() {
    echo " Generating new Ed25519 keypair..."
    
    # Generate private key
    openssl genpkey -algorithm Ed25519 -out matrix_private.pem
    
    # Extract public key
    openssl pkey -in matrix_private.pem -pubout -out matrix_public.pem
    
    # Convert to base64 (raw format)
    PRIVATE_B64=$(openssl pkey -in matrix_private.pem -noout -text | grep -A 5 "priv:" | tail -n +2 | tr -d ' \n:' | xxd -r -p | base64 -w 0)
    PUBLIC_B64=$(openssl pkey -in matrix_public.pem -pubin -noout -text | grep -A 3 "pub:" | tail -n +2 | tr -d ' \n:' | xxd -r -p | base64 -w 0)
    
    echo
    echo " Generated Keys (Base64 encoded):"
    echo "MATRIX_PRIVATE_KEY=$PRIVATE_B64"
    echo "SYNAPSE_PUBLIC_KEY=$PUBLIC_B64"
    
    echo
    echo " Environment Variables:"
    echo "export MATRIX_PRIVATE_KEY=\"$PRIVATE_B64\""
    echo "export SYNAPSE_PUBLIC_KEY=\"$PUBLIC_B64\""
    
    echo
    echo "PEM files saved as:"
    echo "  - matrix_private.pem (private key)"
    echo "  - matrix_public.pem (public key)"
}

encode_existing_key() {
    local keyfile="$1"
    
    if [[ ! -f "$keyfile" ]]; then
        echo " Error: File $keyfile not found"
        exit 1
    fi
    
    echo " Encoding existing key: $keyfile"
    
    # Check if it's a private key
    if openssl pkey -in "$keyfile" -noout -text &>/dev/null; then
        # Private key
        if openssl pkey -in "$keyfile" -noout -text | grep -q "Ed25519"; then
            ENCODED=$(openssl pkey -in "$keyfile" -noout -text | grep -A 5 "priv:" | tail -n +2 | tr -d ' \n:' | xxd -r -p | base64 -w 0)
            echo "Base64 encoded private key: $ENCODED"
        else
            echo " Error: Not an Ed25519 private key"
            exit 1
        fi
    # Check if it's a public key
    elif openssl pkey -pubin -in "$keyfile" -noout -text &>/dev/null; then
        # Public key
        if openssl pkey -pubin -in "$keyfile" -noout -text | grep -q "Ed25519"; then
            ENCODED=$(openssl pkey -pubin -in "$keyfile" -noout -text | grep -A 3 "pub:" | tail -n +2 | tr -d ' \n:' | xxd -r -p | base64 -w 0)
            echo "Base64 encoded public key: $ENCODED"
        else
            echo "Error: Not an Ed25519 public key"
            exit 1
        fi
    else
        echo "Error: Invalid key file format"
        exit 1
    fi
}

show_usage() {
    echo "Usage:"
    echo "  $0                    # Generate new Ed25519 keypair"
    echo "  $0 <key_file.pem>     # Encode existing key file"
    echo
    echo "Examples:"
    echo "  $0                    # Generate new keys"
    echo "  $0 private.pem        # Encode existing private key"
    echo "  $0 public.pem         # Encode existing public key"
}

main() {
    case $# in
        0)
            generate_keypair
            ;;
        1)
            encode_existing_key "$1"
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
