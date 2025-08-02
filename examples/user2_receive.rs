use std::net::IpAddr;

use bitvmx_broker::{
    channel::channel::DualChannel,
    rpc::BrokerConfig,
};
use dns_lookup::lookup_host;

fn main() -> anyhow::Result<()> {
    // Resolve the container IP using hostname
    let container_name = "msg-broker";
    let container_ip = resolve_hostname(container_name)?;
    println!("Resolved '{}' to IP: {}", container_name, container_ip);

    let config = BrokerConfig::new(10000, Some(container_ip));
    let user_1_id = 1;
    let user_2_id = 2;
    let user_2 = DualChannel::new(&config, user_2_id);
    println!("DualChannel over {:#?}:{} for user id: {}", config.ip, config.port, user_2_id);

    let msg_text = "Hello!";
    let msg = user_2.recv().unwrap();
    if msg.is_none() {
        println!("No message received. queue empty.");
        return Ok(());
    }
    let msg = msg.unwrap();
    assert_eq!(msg.0, msg_text);
    assert_eq!(msg.1, user_1_id);
    println!("User 2 received a message from User {} -> msg: {}", user_1_id, msg.0);
    Ok(())
}

fn resolve_hostname(hostname: &str) -> anyhow::Result<IpAddr> {
    let ips = lookup_host(hostname)?;
    ips.into_iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for hostname: {}", hostname))
}