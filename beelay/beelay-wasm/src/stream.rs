use std::{cell::RefCell, rc::Rc};

use beelay_core::{Event, StreamId};
use js_sys::{Function, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsError, JsValue};

use crate::Beelay;

pub struct Stream {
    outbox: StreamOutbox,
    inbox: StreamInbox,
    disconnect_listeners: Vec<Function>,
}

enum StreamOutbox {
    NoListener(Vec<Vec<u8>>),
    Listener(Function),
}

enum StreamInbox {
    AwaitingCreate {
        pending_messages: Vec<Vec<u8>>,
        disconnected: bool,
    },
    Ready(StreamId),
}

pub(super) struct StreamReady {
    pub(super) pending_messages: Vec<Vec<u8>>,
    pub(super) disconnected: bool,
}

impl Stream {
    pub(crate) fn new() -> Self {
        Stream {
            outbox: StreamOutbox::NoListener(Vec::new()),
            inbox: StreamInbox::AwaitingCreate {
                pending_messages: Vec::new(),
                disconnected: false,
            },
            disconnect_listeners: Vec::new(),
        }
    }

    pub(crate) fn set_stream_id(&mut self, stream_id: StreamId) -> StreamReady {
        let last_state = std::mem::replace(&mut self.inbox, StreamInbox::Ready(stream_id));
        match last_state {
            StreamInbox::AwaitingCreate {
                pending_messages,
                disconnected,
            } => StreamReady {
                pending_messages,
                disconnected,
            },
            StreamInbox::Ready(_) => StreamReady {
                pending_messages: Vec::new(),
                disconnected: false,
            },
        }
    }

    pub(crate) fn take_disconnect_listeners(&mut self) -> Vec<Function> {
        std::mem::take(&mut self.disconnect_listeners)
    }

    pub(crate) fn emit_send(&mut self, message: Vec<u8>) {
        match &mut self.outbox {
            StreamOutbox::NoListener(_) => {
                self.inbox = StreamInbox::AwaitingCreate {
                    pending_messages: vec![message],
                    disconnected: false,
                };
            }
            StreamOutbox::Listener(listener) => {
                let _ = listener.call1(&JsValue::null(), &Uint8Array::from(message.as_slice()));
            }
        }
    }
}

#[wasm_bindgen]
pub struct StreamHandle {
    beelay: Beelay,
    stream: Rc<RefCell<Stream>>,
}

#[wasm_bindgen]
impl StreamHandle {
    pub(super) fn new(beelay: crate::Beelay, stream: Rc<RefCell<Stream>>) -> Self {
        StreamHandle { beelay, stream }
    }

    #[wasm_bindgen]
    pub fn on(&self, event: JsValue, callback: JsValue) -> Result<(), JsError> {
        let event_name = event
            .as_string()
            .ok_or_else(|| JsError::new("event name was not a string"))?;
        let callback = callback
            .dyn_into::<Function>()
            .map_err(|_| JsError::new("callback was not a function"))?;
        match event_name.as_str() {
            "message" => {
                let messages = {
                    let mut stream = self.stream.borrow_mut();
                    if let StreamOutbox::NoListener(messages) = &mut stream.outbox {
                        let messages = std::mem::take(messages);
                        stream.outbox = StreamOutbox::Listener(callback.clone());
                        messages
                    } else {
                        return Err(JsError::new("stream already has a message  listener"));
                    }
                };
                for message in messages {
                    callback
                        .call1(&JsValue::NULL, &Uint8Array::from(message.as_slice()))
                        .map_err(|_| JsError::new("callback failed"))?;
                }
                Ok(())
            }
            "disconnect" => {
                let mut stream = self.stream.borrow_mut();
                stream.disconnect_listeners.push(callback);
                Ok(())
            }
            other => return Err(JsError::new(&format!("unknown event: {}", other))),
        }
    }

    #[wasm_bindgen]
    pub fn recv(&self, msg: JsValue) -> Result<(), JsError> {
        let msg = msg
            .dyn_into::<Uint8Array>()
            .map_err(|_| JsError::new("message was not a Uint8Array"))?
            .to_vec();
        let stream_id = {
            let mut stream = self.stream.borrow_mut();
            match stream.inbox {
                StreamInbox::AwaitingCreate {
                    ref mut pending_messages,
                    ..
                } => {
                    pending_messages.push(msg);
                    return Ok(());
                }
                StreamInbox::Ready(stream_id) => stream_id,
            }
        };
        let (_, event) = Event::handle_message(stream_id, msg);
        self.beelay.handle_event(event);
        Ok(())
    }

    #[wasm_bindgen]
    pub fn disconnect(&self) -> Result<(), JsError> {
        let stream_id = {
            let mut stream = self.stream.borrow_mut();
            match stream.inbox {
                StreamInbox::AwaitingCreate {
                    ref mut disconnected,
                    ..
                } => {
                    *disconnected = true;
                    return Ok(());
                }
                StreamInbox::Ready(stream_id) => stream_id,
            }
        };
        let (_, event) = Event::disconnect_stream(stream_id);
        self.beelay.handle_event(event);
        Ok(())
    }
}
