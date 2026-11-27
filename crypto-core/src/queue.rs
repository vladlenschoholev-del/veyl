use std::fmt;

use getrandom::fill;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, Result};

#[derive(Clone, Eq, PartialEq)]
pub struct QueueCredentials {
    pub queue_id: [u8; 32],
    write_capability: Zeroizing<[u8; 32]>,
}

impl QueueCredentials {
    pub fn generate() -> Result<Self> {
        let mut queue_id = [0u8; 32];
        let mut write_capability = [0u8; 32];
        fill(&mut queue_id).map_err(|_| CryptoError::Randomness)?;
        fill(&mut write_capability).map_err(|_| {
            queue_id.zeroize();
            CryptoError::Randomness
        })?;
        Ok(Self {
            queue_id,
            write_capability: Zeroizing::new(write_capability),
        })
    }

    pub fn write_capability(&self) -> &[u8; 32] {
        &self.write_capability
    }
}

impl fmt::Debug for QueueCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueueCredentials")
            .field("queue_id", &self.queue_id)
            .field("write_capability", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectionalQueues {
    pub send: QueueCredentials,
    pub receive: QueueCredentials,
}

impl DirectionalQueues {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            send: QueueCredentials::generate()?,
            receive: QueueCredentials::generate()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directional_queue_credentials_are_independent_and_redacted() {
        let queues = DirectionalQueues::generate().unwrap();
        assert_ne!(queues.send.queue_id, queues.receive.queue_id);
        assert_ne!(
            queues.send.write_capability(),
            queues.receive.write_capability()
        );
        assert!(
            !format!("{queues:?}").contains(&format!("{:02x?}", queues.send.write_capability()))
        );
    }
}
