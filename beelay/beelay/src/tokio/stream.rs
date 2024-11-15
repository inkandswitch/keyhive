use beelay_core::Audience;
use bytes::Buf;
use futures::StreamExt;

use crate::Forwarding;

impl crate::Beelay {
    pub async fn accept_tokio_io<Io>(
        &self,
        io: Io,
        receive_audience: Option<String>,
        forwarding: Forwarding,
    ) -> Result<(), error::CodecError>
    where
        Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send,
    {
        let codec = Codec;
        let framed = tokio_util::codec::Framed::new(io, codec);

        let (sink, stream) = framed.split();

        self.accept_stream(stream, sink, receive_audience, forwarding)
            .driver
            .await?;

        Ok(())
    }

    pub async fn connect_tokio_io<Io>(
        &self,
        io: Io,
        remote_audience: Audience,
        forwarding: Forwarding,
    ) -> Result<(), error::CodecError>
    where
        Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send,
    {
        let codec = Codec;
        let framed = tokio_util::codec::Framed::new(io, codec);

        let (sink, stream) = framed.split();

        self.connect_stream(stream, sink, remote_audience, forwarding)
            .driver
            .await?;

        Ok(())
    }
}

pub(crate) struct Codec;

impl tokio_util::codec::Decoder for Codec {
    type Item = Vec<u8>;

    type Error = error::CodecError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        // Read the length prefix
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&src[..4]);
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Check if we have enough data for this message
        if src.len() < len + 4 {
            src.reserve(len + 4 - src.len());
            return Ok(None);
        }

        // Parse the message
        let data = src[4..len + 4].to_vec();
        src.advance(len + 4);
        Ok(Some(data))
    }
}

impl tokio_util::codec::Encoder<Vec<u8>> for Codec {
    type Error = error::CodecError;

    fn encode(&mut self, msg: Vec<u8>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let len = msg.len() as u32;
        let len_slice = len.to_be_bytes();
        dst.reserve(4 + len as usize);
        dst.extend_from_slice(&len_slice);
        dst.extend_from_slice(&msg);
        Ok(())
    }
}

mod error {
    use crate::error::ConnectionError;

    pub enum CodecError {
        Io(std::io::Error),
        Decode(beelay_core::connection::error::Receive),
        DriverStopped,
    }

    impl std::fmt::Display for CodecError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(err) => write!(f, "IO error: {}", err),
                Self::Decode(err) => write!(f, "Decode error: {}", err),
                Self::DriverStopped => write!(f, "Driver stopped"),
            }
        }
    }

    impl std::fmt::Debug for CodecError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for CodecError {}

    impl From<std::io::Error> for CodecError {
        fn from(value: std::io::Error) -> Self {
            Self::Io(value)
        }
    }

    impl From<beelay_core::connection::error::Receive> for CodecError {
        fn from(value: beelay_core::connection::error::Receive) -> Self {
            Self::Decode(value)
        }
    }

    impl From<ConnectionError<CodecError, CodecError>> for CodecError {
        fn from(value: ConnectionError<CodecError, CodecError>) -> Self {
            match value {
                ConnectionError::Recv(err) => err,
                ConnectionError::Send(err) => err,
                ConnectionError::DriverStopped => Self::DriverStopped,
            }
        }
    }
}
