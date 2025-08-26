use bitvmx_broker::rpc::tls_helper::Cert;
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
    //ASK: no puedo generar con RSA porque no lo soporta
    init_tracing()?;
    Cert::generate_key_file("../certs", "services.key")?;

    Ok(())
}
