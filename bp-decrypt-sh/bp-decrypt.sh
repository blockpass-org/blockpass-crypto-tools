#!/bin/bash
set -e

while getopts i:m:o:k: flag
do
    case "${flag}" in
        i) in=${OPTARG};;
        m) meta=${OPTARG};;
        o) out=${OPTARG};;
        k) key=${OPTARG};;
    esac
done

if [ -z "$in" ] ; then
 echo "Missing input file"
 exit 1
fi

if [ -z "$out" ] ; then
 echo "Missing output file"
 exit 1
fi

if [ -z "$key" ] ; then
 echo "Missing private key"
 exit 1
fi

if [ -z "$meta" ] ; then
 echo "Missing metadata file"
 exit 1
fi

echo "Input parameters:"
echo " - Encrypted File: $in"
echo " - Metadata File: $meta"
echo " - Private Key File: $key"
echo " - Output File: $out"

# Parse meta
wrappedKey=$(grep '"wrappedKey":' $meta | cut -d '"' -f 4)
ivHex=$(grep '"iv":' $meta | cut -d '"' -f 4)
checksum=$(grep '"zipContentSHA256":' $meta | cut -d '"' -f 4)

echo "=================="
echo "Parsing metadata"
if [ -z "$wrappedKey" ] ; then
 echo "Failed to parse encrypted key from $meta"
 exit 1
fi

if [ -z "$ivHex" ] ; then
 echo "Failed to parse ivHex from $meta"
 exit 1
fi

if [ -z "$checksum" ] ; then
 echo "Failed to parse checksum from $meta"
 exit 1
fi
echo "Metadata parsing successfull"

# Decode
echo "=================="
echo "Decoding"
echo "$wrappedKey" > tmp.txt

openssl base64 -d -A -in tmp.txt -out tmp.bin

decryptedKey=$(openssl rsautl -decrypt -inkey "$key" -in tmp.bin -oaep)

openssl enc -d -aes-256-cbc -in "$in" -out "$out" -K "$decryptedKey" -iv "$ivHex"

# Cleanup
rm tmp.txt
rm tmp.bin

echo "Decoding successfull: $out"

# Checksum
zipChecksum=$(openssl dgst -sha256 "$out"| awk '{print $NF}')

echo "=================="
if [ "$zipChecksum" = "$checksum" ]; then
   
    echo "Checksum: MATCHED"
    echo "- Checksum: $checksum"
    echo "- Decoded: $zipChecksum"
else
    echo "Checksum: MISSMATCHED"
    echo "- Checksum: $checksum"
    echo "- Decoded: $zipChecksum"
fi