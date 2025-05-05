@echo off
setlocal enabledelayedexpansion

REM 🔧 Create certs folder if it doesn't exist
if not exist "certs" (
    mkdir certs
)

REM 🔧 Generating CA cert...
openssl genrsa -out certs/ca.key 2048
openssl req -x509 -new -key certs/ca.key -sha256 -days 3650 -out certs/ca.pem -config openssl-ca.cnf

REM 🔧 Generating server cert...
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr -config openssl-server.cnf
openssl x509 -req -in certs/server.csr -CA certs/ca.pem -CAkey certs/ca.key -CAcreateserial -out certs/server.pem -days 365 -sha256 -extfile openssl-server.cnf -extensions v3_server

REM 🔧 Generating client certs
set clients=peer1 peer2
(for %%C in (%clients%) do (
    echo 🔧 Generating cert for %%C...

    openssl genrsa -out certs/%%C.key 2048
    openssl req -new -key certs/%%C.key -out certs/%%C.csr -config openssl-client.cnf -subj "/CN=%%C"
    openssl x509 -req -in certs/%%C.csr -CA certs/ca.pem -CAkey certs/ca.key -CAcreateserial -out certs/%%C.pem -days 365 -sha256 -extfile openssl-client.cnf -extensions v3_client
))

REM 🔧 Generating whitelist.yaml
echo 🔧 Creating whitelist.yaml...
echo. > certs/whitelist.yaml
for %%C in (%clients%) do (
    echo Hashing %%C cert...
    openssl x509 -in certs/%%C.pem -outform der | openssl dgst -sha256 -r | for /f "tokens=1" %%H in ('more') do (
        echo %%H: %%C >> certs/whitelist.yaml
    )
)

echo Done. All certs, keys, and whitelist.yaml are in the certs/ folder.
pause
