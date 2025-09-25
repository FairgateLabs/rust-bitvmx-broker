use bitvmx_broker::rpc::tls_helper::Cert;
use rsa::rand_core::OsRng;
use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

pub fn init_tracing() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .parse("info,tarpc=off") // Include everything at "info" except `libp2p`
        .expect("Invalid filter");

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;

    Ok(())
}
fn main() -> anyhow::Result<()> {
    init_tracing()?;
    let mut rng = OsRng;
    let rsa_bits = 2048;
    Cert::generate_key_file("./certs", "services", &mut rng, rsa_bits)?;

    Ok(())
}
