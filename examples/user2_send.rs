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

    let msg_2_text = "How are you?";
    user_2.send(user_1_id, msg_2_text.to_string()).unwrap();
    println!("\nUser 2 send a message to User {} -> msg: {}", user_1_id, msg_2_text);
    Ok(())
}

fn resolve_hostname(hostname: &str) -> anyhow::Result<IpAddr> {
    let ips = lookup_host(hostname)?;
    ips.into_iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for hostname: {}", hostname))
}