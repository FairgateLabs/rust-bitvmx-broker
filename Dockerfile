FROM rust:latest

RUN apt-get update && \
    apt-get install -y \
    wget build-essential git pkg-config libssl-dev clang jq dnsutils iproute2 net-tools nano netcat-openbsd iputils-ping

WORKDIR /broker

COPY . .

# add your aliases to root’s bashrc (dev)
RUN printf "\n\
# custom shortcuts\n\
alias ll='ls -alh'\n\
alias nn='netstat -antup | grep LISTEN'\n" \
  >> /root/.bashrc

CMD cargo build --release

ENTRYPOINT ["/bin/bash", "-c"]
# docker run your-image "cd /some/dir && ./another-script.sh"