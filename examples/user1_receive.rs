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
    let user_1 = DualChannel::new(&config, user_1_id);
    println!("DualChannel over {:#?}:{} for user id: {}", config.ip, config.port, user_1_id);

    let msg_2_text = "How are you?";
    let msg_2 = user_1.recv().unwrap();
    if msg_2.is_none() {
        println!("No message received. queue empty.");
        return Ok(());
    }
    let msg_2 = msg_2.unwrap();
    assert_eq!(msg_2.0, msg_2_text);
    assert_eq!(msg_2.1, user_2_id);
    println!("User 1 received a message from User {} -> msg: {}", user_2_id, msg_2.0);
    Ok(())
}

fn resolve_hostname(hostname: &str) -> anyhow::Result<IpAddr> {
    let ips = lookup_host(hostname)?;
    ips.into_iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for hostname: {}", hostname))
}