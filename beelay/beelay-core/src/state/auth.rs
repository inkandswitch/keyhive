use std::{cell::RefCell, rc::Rc};

use ed25519_dalek::SigningKey;

use crate::{
    auth,
    serialization::{Encode, Parse},
    Audience, UnixTimestamp,
};

pub(crate) struct Auth<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: &'a Rc<RefCell<super::State<R>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Auth<'a, R> {
    pub(crate) fn authenticate_received_msg<T>(
        &self,
        msg: auth::Signed<auth::Message>,
        receive_audience: Option<Audience>,
    ) -> Result<crate::auth::Authenticated<T>, crate::auth::manager::ReceiveMessageError>
    where
        for<'b> T: Parse<'b>,
    {
        let now = self.state.borrow().now.clone();
        self.state
            .borrow_mut()
            .auth
            .receive(now, msg, receive_audience)
    }

    pub(crate) fn sign_message<T>(
        &self,
        audience: crate::Audience,
        msg: T,
    ) -> crate::auth::signed::Signed<crate::auth::message::Message>
    where
        T: Encode,
    {
        let now = self.state.borrow().now.clone();
        self.state
            .borrow_mut()
            .auth
            .send(now, audience, msg.encode())
    }

    pub(crate) fn signing_key(&self) -> SigningKey {
        self.state.borrow().auth.signing_key.clone()
    }

    pub(crate) fn update_offset(&self, remote_audience: Audience, their_clock: UnixTimestamp) {
        let now = self.state.borrow().now.clone();
        self.state
            .borrow_mut()
            .auth
            .update_offset(now, remote_audience, their_clock);
    }
}
