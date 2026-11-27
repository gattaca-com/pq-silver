use std::net::SocketAddr;

use flux_network::{NetworkCore, NetworkEvent};
use flux_sse::{Sse, SseEvent};
use serde::Deserialize;
use silver_common::json_fields::{bytes, uint64};

const EVENTS_PATH: &str = "/eth/v1/events";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Head {
    #[serde(deserialize_with = "uint64")]
    pub slot: u64,
    #[serde(deserialize_with = "bytes")]
    pub block: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    pub previous_duty_dependent_root: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    pub current_duty_dependent_root: [u8; 32],
}

#[derive(Deserialize)]
struct PayloadAvailable {
    #[serde(deserialize_with = "uint64")]
    slot: u64,
}

/// A node event the duties act on.
pub enum ChainEvent {
    Head(Head),
    /// The slot's payload envelope arrived, so its PTC can vote.
    PayloadAvailable {
        slot: u64,
    },
}

pub struct EventStream {
    sse: Sse,
    /// The refusal last logged, so a node that keeps refusing logs once.
    refused_with: Option<u16>,
}

impl EventStream {
    pub fn open(
        net: &mut NetworkCore,
        addr: SocketAddr,
        authority: &str,
        tls_host: Option<&str>,
    ) -> Self {
        let mut sse = Sse::new(addr, EVENTS_PATH)
            .with_query(&[("topics", "head"), ("topics", "execution_payload_available")])
            .with_header("Host", authority);
        match tls_host {
            Some(host) => sse.connect_tls(net, host),
            None => sse.connect(net),
        }
        Self { sse, refused_with: None }
    }

    pub fn on_event(&mut self, event: &NetworkEvent<'_>) -> bool {
        self.sse.on_event(event)
    }

    pub fn drive(
        &mut self,
        net: &mut NetworkCore,
        url: &str,
        mut on_event: impl FnMut(ChainEvent),
    ) {
        let refused_with = &mut self.refused_with;
        self.sse.drive(net, |event| match event {
            SseEvent::Open => {
                *refused_with = None;
                silver_log::info!(url, "event stream open");
            }
            SseEvent::Message { kind: "head", data } => match serde_json::from_slice(data) {
                Ok(head) => on_event(ChainEvent::Head(head)),
                Err(e) => silver_log::warn!(url, %e, "malformed head event"),
            },
            SseEvent::Message { kind: "execution_payload_available", data } => {
                match serde_json::from_slice::<PayloadAvailable>(data) {
                    Ok(PayloadAvailable { slot }) => {
                        on_event(ChainEvent::PayloadAvailable { slot })
                    }
                    Err(e) => silver_log::warn!(url, %e, "malformed execution_payload_available"),
                }
            }
            SseEvent::Message { .. } => {}
            SseEvent::Gap => {
                silver_log::warn!(url, "event stream dropped; its events until reopen are lost")
            }
            SseEvent::Status(status) => {
                if refused_with.replace(status) != Some(status) {
                    silver_log::warn!(url, status, "event stream refused");
                }
            }
        });
    }
}

#[cfg(test)]
pub mod tests {
    pub const EVENTS_ROUTE: &str = "/eth/v1/events?topics=head&topics=execution_payload_available";

    pub fn payload_available_event(slot: u64) -> String {
        format!(
            "event: execution_payload_available\ndata: {{\"slot\":\"{slot}\",\"block_root\":\"0x{}\"}}\n\n",
            hex::encode([0xab; 32])
        )
    }

    pub fn head_event(slot: u64, block: u8) -> String {
        format!(
            "event: head\ndata: {{\"slot\":\"{slot}\",\"block\":\"0x{}\",\"state\":\"0x{}\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0x{}\",\"current_duty_dependent_root\":\"0x{}\",\"execution_optimistic\":false}}\n\n",
            hex::encode([block; 32]),
            hex::encode([0; 32]),
            hex::encode([0xd0; 32]),
            hex::encode([0xd1; 32])
        )
    }
}
