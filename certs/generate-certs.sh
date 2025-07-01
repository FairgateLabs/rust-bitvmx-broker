# TODO: Update to hash public key instead of the entire certificate
#!/bin/bash
set -e

echo "Generating self-signed server cert..."
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.pem -days 365 -subj "/CN=server"

clients=("peer1" "peer2")

echo "Generating self-signed client certs..."
for client in "${clients[@]}"; do
    echo "  ➤ $client"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$client.key" -out "$client.pem" -days 365 -subj "/CN=$client"
done

echo "Creating allowlist.yaml..."
> allowlist.yaml

echo "Adding server fingerprint..."
openssl x509 -in server.pem -outform der | openssl dgst -sha256 -r | awk '{print $1": server"}' >> allowlist.yaml

echo "Adding client fingerprints..."
for client in "${clients[@]}"; do
    echo "  ➤ $client"
    openssl x509 -in "$client.pem" -outform der | openssl dgst -sha256 -r | awk -v name="$client" '{print $1": "name}' >> allowlist.yaml
done

echo "Done. Certs, keys, and allowlist.yaml are in the current folder."
