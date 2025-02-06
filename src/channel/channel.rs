use crate::rpc::{client::Client, BrokerConfig};

pub struct DualChannel {
    client: Client,
    my_id: u32,
}

impl DualChannel {
    pub fn new(config: &BrokerConfig, my_id: u32) -> Self {
        let client = Client::new(config);
        Self { client, my_id }
    }

    pub fn send(&self, dest: u32, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client.send_msg(self.my_id, dest, msg)
    }

    pub fn recv(&self) -> Result<Option<String>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.client.get_msg(self.my_id)? {
            self.client.ack(self.my_id, msg.uid)?;
            Ok(Some(msg.msg))
        } else {
            Ok(None)
        }
    }
}
