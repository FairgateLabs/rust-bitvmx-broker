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

REM Extract and hash only the public key bitstring
echo Hashing server public key...
openssl x509 -in server.pem -pubkey -noout ^
    | openssl rsa -pubin -outform DER 2>nul ^
    | openssl asn1parse -inform DER -strparse 19 -out pubkey.raw
openssl dgst -sha256 -r pubkey.raw | for /f "tokens=1" %%H in ('more') do (
    echo %%H: server >> allowlist.yaml
)


REM Do the same for each client
for %%C in (%clients%) do (
    echo Hashing %%C public key...
    openssl x509 -in %%C.pem -pubkey -noout ^
        | openssl rsa -pubin -outform DER 2>nul ^
        | openssl asn1parse -inform DER -strparse 19 -out %%C.raw
    openssl dgst -sha256 -r %%C.raw | for /f "tokens=1" %%H in ('more') do (
        echo %%H: %%C >> allowlist.yaml
    )
)


echo Done. All certs, keys, and allowlist.yaml are in the folder.
pause
