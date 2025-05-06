@echo off
setlocal enabledelayedexpansion

REM Generate self-signed server cert
echo Generating self-signed server cert...
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.pem -days 365 -subj "/CN=server"

REM Generate self-signed client certs
set clients=peer1 peer2
for %%C in (%clients%) do (
    echo Generating self-signed cert for %%C...
    openssl req -x509 -newkey rsa:2048 -nodes -keyout %%C.key -out %%C.pem -days 365 -subj "/CN=%%C"
)

REM Create allowlist.yaml
echo Creating allowlist.yaml...
echo. > allowlist.yaml

REM Add server fingerprint
echo Hashing server cert...
openssl x509 -in server.pem -outform der | openssl dgst -sha256 -r | for /f "tokens=1" %%H in ('more') do (
    echo %%H: server >> allowlist.yaml
)

REM Add each client fingerprint
for %%C in (%clients%) do (
    echo Hashing %%C cert...
    openssl x509 -in %%C.pem -outform der | openssl dgst -sha256 -r | for /f "tokens=1" %%H in ('more') do (
        echo %%H: %%C >> allowlist.yaml
    )
)

echo Done. All certs, keys, and allowlist.yaml are in the  folder.
pause
