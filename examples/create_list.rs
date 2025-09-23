use bitvmx_broker::identification::routing::{RouteIdentifier, WildCard};
use bitvmx_broker::identification::{
    allow_list::AllowList, identifier::Identifier, routing::RoutingTable,
};
use std::io::{self, Write};
use std::net::IpAddr;
use std::str::FromStr;
use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

fn init_tracing() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .parse("info,tarpc=off")
        .expect("Invalid filter");

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    init_tracing()?;

    // Start empty allowlist & routing table
    let allowlist = AllowList::new();
    let routing_table = RoutingTable::new();

    let mut input = String::new();

    println!("=== Interactive Broker CLI ===");
    println!("Commands:");
    println!("  allow <pubkey_hash> <ip>  -> add to allowlist");
    println!("  route <from> <to>         -> add route");
    println!("  show allow                -> show allowlist");
    println!("  show routes               -> show routing table");
    println!("  quit and save             -> exit and save to files");

    loop {
        input.clear();
        print!("> ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut input)?;
        let line = input.trim();
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("allow") => {
                if let Some(pubk) = parts.next() {
                    match parts.next() {
                        Some(ip_str) => {
                            if ip_str == "~" {
                                allowlist.lock().unwrap().add_wildcard(pubk.to_string());
                                println!("Added {}:~", pubk);
                            } else {
                                match IpAddr::from_str(ip_str) {
                                    Ok(ip) => {
                                        allowlist.lock().unwrap().add(pubk.to_string(), ip);
                                        println!("Added {}:{}", pubk, ip);
                                    }
                                    Err(_) => println!("Invalid IP address"),
                                }
                            }
                        }
                        None => {
                            allowlist.lock().unwrap().add_wildcard(pubk.to_string());
                            println!("Added {}:~", pubk);
                        }
                    }
                } else {
                    println!("Usage: allow <pubkey_hash> [ip|~]");
                }
            }
            Some("route") => {
                if let (Some(from_str), Some(to_str)) = (parts.next(), parts.next()) {
                    let from = match RouteIdentifier::from_str(from_str) {
                        Ok(val) => val,
                        Err(e) => {
                            println!("Invalid 'from' identifier: {}", e);
                            continue;
                        }
                    };
                    let to = match RouteIdentifier::from_str(to_str) {
                        Ok(val) => val,
                        Err(e) => {
                            println!("Invalid 'to' identifier: {}", e);
                            continue;
                        }
                    };

                    // determine wildcard mode
                    let wild_card = match (from.id.is_none(), to.id.is_none()) {
                        (false, false) => WildCard::No,
                        (true, false) => WildCard::From,
                        (false, true) => WildCard::To,
                        (true, true) => WildCard::Both,
                    };

                    // unwrap Option<u8> safely since identifiers with None are handled by wildcards
                    let from_id = from.id.unwrap_or(0);
                    let to_id = to.id.unwrap_or(0);

                    let from_ident = Identifier::new(from.pubkey_hash.clone(), from_id);
                    let to_ident = Identifier::new(to.pubkey_hash.clone(), to_id);

                    routing_table
                        .lock()
                        .unwrap()
                        .add_route(from_ident, to_ident, wild_card);

                    println!("Added route {} -> {}", from_str, to_str);
                } else {
                    println!("Usage: route <from> <to>");
                }
            }
            Some("show") => match parts.next() {
                Some("allow") => {
                    let list = allowlist.lock().unwrap();
                    println!("AllowList: {:?}", *list);
                }
                Some("routes") => {
                    let table = routing_table.lock().unwrap();
                    println!("RoutingTable: {:?}", *table);
                }
                _ => println!("Usage: show <allow|routes>"),
            },
            Some("quit") => {
                allowlist
                    .lock()
                    .unwrap()
                    .generate_yaml("allowlist.yaml")
                    .unwrap();
                routing_table
                    .lock()
                    .unwrap()
                    .save_to_file("routing_table.yaml")
                    .unwrap();
                break;
            }
            Some(cmd) => println!("Unknown command: {}", cmd),
            None => continue,
        }
    }

    println!("Exiting CLI...");
    Ok(())
}
