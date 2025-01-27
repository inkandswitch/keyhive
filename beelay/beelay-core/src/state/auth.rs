use std::{borrow::Cow, cell::RefCell, rc::Rc};

use crate::{
    auth,
    serialization::{Encode, Parse},
    Audience, UnixTimestamp,
};

pub(crate) struct Auth<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: Cow<'a, Rc<RefCell<super::State<R>>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Auth<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Self { state }
    }

    pub(crate) fn authenticate_received_msg<T>(
        &self,
        now: UnixTimestamp,
        msg: auth::Signed<auth::Message>,
        receive_audience: Option<Audience>,
    ) -> Result<crate::auth::Authenticated<T>, crate::auth::manager::ReceiveMessageError>
    where
        for<'b> T: Parse<'b>,
    {
        self.state
            .borrow_mut()
            .auth
            .receive(now, msg, receive_audience)
    }

    pub(crate) async fn sign_message<T>(
        &self,
        now: UnixTimestamp,
        audience: crate::Audience,
        msg: T,
    ) -> crate::auth::signed::Signed<crate::auth::message::Message>
    where
        T: Encode,
    {
        let send = self
            .state
            .borrow_mut()
            .auth
            .send(now, audience, msg.encode());
        send.await
    }

    pub(crate) fn update_offset(
        &self,
        now: UnixTimestamp,
        remote_audience: Audience,
        their_clock: UnixTimestamp,
    ) {
        self.state
            .borrow_mut()
            .auth
            .update_offset(now, remote_audience, their_clock);
    }
}
