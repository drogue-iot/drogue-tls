use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::{
    alert::*,
    handshake::{certificate::Certificate, certificate_request::CertificateRequest},
};
use crate::{
    buffer::CryptoBuffer,
    config::{Config, TlsCipherSuite},
};
use crate::{AsyncRead, AsyncWrite, TlsError};
use core::fmt::Debug;
use digest::generic_array::typenum::Unsigned;
use p256::ecdh::EphemeralSecret;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

use crate::application_data::ApplicationData;
use crate::content_types::ContentType;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadInPlace, NewAead};
use core::fmt::Formatter;
use digest::FixedOutput;
use heapless::{consts, spsc::Queue};

enum State {
    ClientHello,
    ServerHello(EphemeralSecret),
    ServerCert,
    ServerFinished,
    ClientFinished,
    ApplicationData,
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match &self {
            State::ClientHello => write!(f, "ClientHello"),
            State::ServerHello(_) => write!(f, "ServerHello"),
            State::ServerCert => write!(f, "ServerCert"),
            State::ServerFinished => write!(f, "ServerFinished"),
            State::ClientFinished => write!(f, "ClientFinished"),
            State::ApplicationData => write!(f, "ApplicationData"),
        }
    }
}

// Split records at 8k of data
const FRAME_MTU: usize = 8192;

pub struct TlsConnection<'a, RNG, Socket, CipherSuite, const FRAME_BUF_LEN: usize>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    config: &'a Config<'a, RNG, CipherSuite>,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    frame_buf: [u8; FRAME_BUF_LEN],
    state: Option<State>,
}

impl<'a, RNG, Socket, CipherSuite, const FRAME_BUF_LEN: usize>
    TlsConnection<'a, RNG, Socket, CipherSuite, FRAME_BUF_LEN>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite + 'static,
{
    pub fn new(config: &'a Config<'a, RNG, CipherSuite>, delegate: Socket) -> Self {
        Self {
            delegate,
            config,
            state: Some(State::ClientHello),
            key_schedule: KeySchedule::new(),
            frame_buf: [0; FRAME_BUF_LEN],
        }
    }

    async fn transmit<'m>(
        &mut self,
        record: &ClientRecord<'_, 'm, RNG, CipherSuite>,
    ) -> Result<(), TlsError> {
        let tx_buf = &mut self.frame_buf[..];
        let key_schedule = &mut self.key_schedule;
        let delegate = &mut self.delegate;

        let (len, range) = record.encode(tx_buf, |buf| Self::encrypt(key_schedule, buf))?;

        if let Some(range) = range {
            Digest::update(key_schedule.transcript_hash(), &tx_buf[range]);
        }
        trace!(
            "**** transmit {} bytes, hash={:x?}",
            len,
            key_schedule.transcript_hash().clone().finalize()
        );

        delegate.write(&tx_buf[..len]).await?;

        key_schedule.increment_write_counter();
        Ok(())
    }

    fn encrypt(
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        buf: &mut CryptoBuffer<'_>,
    ) -> Result<usize, TlsError> {
        let client_key = key_schedule.get_client_key()?;
        let nonce = &key_schedule.get_client_nonce()?;
        trace!("encrypt key {:02x?}", client_key);
        trace!("encrypt nonce {:02x?}", nonce);
        trace!("plaintext {} {:02x?}", buf.len(), buf.as_slice(),);
        //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
        let crypto = CipherSuite::Cipher::new(&client_key);
        let len = buf.len() + <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize();

        if len > buf.capacity() {
            return Err(TlsError::InsufficientSpace);
        }

        trace!(
            "output size {}",
            <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize()
        );
        let len_bytes = (len as u16).to_be_bytes();
        let additional_data = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ];

        crypto
            .encrypt_in_place(nonce, &additional_data, buf)
            .map_err(|_| TlsError::InvalidApplicationData)?;
        Ok(buf.len())
    }

    fn decrypt_record<'m>(
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        records: &mut Queue<
            ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
            consts::U4,
        >,
        record: ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
    ) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        if let ServerRecord::ApplicationData(ApplicationData {
            header,
            data: mut app_data,
        }) = record
        {
            trace!("decrypting {:x?} with {}", &header, app_data.len());
            //let crypto = Aes128Gcm::new(&self.key_schedule.get_server_key());
            let crypto = CipherSuite::Cipher::new(&key_schedule.get_server_key()?);
            let nonce = &key_schedule.get_server_nonce();
            trace!("server write nonce {:x?}", nonce);
            crypto
                .decrypt_in_place(&key_schedule.get_server_nonce()?, &header, &mut app_data)
                .map_err(|_| TlsError::CryptoError)?;
            //            trace!("decrypted with padding {:x?}", app_data);
            let padding = app_data
                .as_slice()
                .iter()
                .enumerate()
                .rfind(|(_, b)| **b != 0);
            if let Some((index, _)) = padding {
                app_data.truncate(index + 1);
            };
            //trace!("decrypted {:x?}", data);

            let content_type = ContentType::of(*app_data.as_slice().last().unwrap())
                .ok_or(TlsError::InvalidRecord)?;

            match content_type {
                ContentType::Handshake => {
                    // Decode potentially coaleced handshake messages
                    let data = &app_data.as_slice()[..app_data.len() - 1];
                    let mut buf = ParseBuffer::new(data);
                    while buf.remaining() > 1 {
                        let mut inner = ServerHandshake::parse(&mut buf);
                        if let Ok(ServerHandshake::Finished(ref mut finished)) = inner {
                            trace!("Server finished hash: {:x?}", finished.hash);
                            finished
                                .hash
                                .replace(key_schedule.transcript_hash().clone().finalize());
                        }
                        info!("===> inner ==> {:?}", inner);
                        //if hash_later {
                        Digest::update(key_schedule.transcript_hash(), &data[..data.len()]);
                        info!("hash {:02x?}", &data[..data.len()]);
                        records
                            .enqueue(ServerRecord::Handshake(inner.unwrap()))
                            .map_err(|_| TlsError::EncodeError)?
                    }
                    //}
                }
                ContentType::ApplicationData => {
                    app_data.truncate(app_data.len() - 1);
                    let inner = ApplicationData::new(app_data, header);
                    records
                        .enqueue(ServerRecord::ApplicationData(inner))
                        .map_err(|_| TlsError::EncodeError)?
                }
                ContentType::Alert => {
                    let data = &app_data.as_slice()[..app_data.len() - 1];
                    let mut buf = ParseBuffer::new(data);
                    let alert = Alert::parse(&mut buf)?;
                    records
                        .enqueue(ServerRecord::Alert(alert))
                        .map_err(|_| TlsError::EncodeError)?
                }
                _ => return Err(TlsError::Unimplemented),
            }
            //debug!("decrypted {:?} --> {:x?}", content_type, data);
            key_schedule.increment_read_counter();
        } else {
            records.enqueue(record).map_err(|_| TlsError::EncodeError)?
        }
        Ok(())
    }

    async fn fetch_records<'m>(
        delegate: &mut Socket,
        rx_buf: &'m mut [u8],
        records: &mut Queue<
            ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
            consts::U4,
        >,
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError>
    where
        'a: 'm,
    {
        if let Some(record) = records.dequeue() {
            Ok(record)
        } else {
            let record = Self::fetch_record(delegate, rx_buf, key_schedule).await?;
            Self::decrypt_record(key_schedule, records, record)?;
            if let Some(record) = records.dequeue() {
                Ok(record)
            } else {
                Err(TlsError::DecodeError)
            }
        }
    }

    async fn fetch_record<'m>(
        delegate: &mut Socket,
        rx_buf: &'m mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError> {
        Ok(ServerRecord::read(delegate, rx_buf, key_schedule.transcript_hash()).await?)
    }

    pub async fn open<'m>(&mut self) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        loop {
            let state = self.state.take().unwrap();
            info!("From: {:?}", &state);
            let next_state = self.handshake(state).await?;
            info!("To: {:?}", &next_state);
            //            info!("State {:?} -> {:?}", &state, &next_state);
            self.state.replace(next_state);
            if let Some(State::ApplicationData) = self.state {
                break;
            }
        }

        Ok(())
    }

    async fn handshake<'m>(&mut self, state: State) -> Result<State, TlsError>
    where
        'a: 'm,
    {
        match state {
            State::ClientHello => {
                self.key_schedule.initialize_early_secret()?;
                let client_hello = ClientRecord::client_hello(&self.config);

                self.transmit(&client_hello).await?;

                if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello)) =
                    client_hello
                {
                    Ok(State::ServerHello(client_hello.secret))
                } else {
                    Err(TlsError::EncodeError)
                }
            }
            State::ServerHello(secret) => match Self::fetch_record(
                &mut self.delegate,
                &mut self.frame_buf,
                &mut self.key_schedule,
            )
            .await?
            {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::ServerHello(server_hello) => {
                        info!("********* ServerHello");
                        let shared = server_hello
                            .calculate_shared_secret(&secret)
                            .ok_or(TlsError::InvalidKeyShare)?;
                        self.key_schedule
                            .initialize_handshake_secret(shared.as_bytes())?;
                        Ok(State::ServerCert)
                    }
                    e => Err(TlsError::InvalidHandshake),
                },
                _ => Err(TlsError::InvalidRecord),
            },
            State::ClientFinished => {
                let client_finished = self
                    .key_schedule
                    .create_client_finished()
                    .map_err(|_| TlsError::InvalidHandshake)?;

                let client_finished =
                    ClientHandshake::<RNG, CipherSuite>::Finished(client_finished);
                let client_finished = ClientRecord::EncryptedHandshake(client_finished);

                info!("Transmitting finished frame");

                self.transmit(&client_finished).await?;

                self.key_schedule.initialize_master_secret()?;
                Ok(State::ApplicationData)
            }
            State::ApplicationData => Ok(State::ApplicationData),
            state => {
                let frame_buf = &mut self.frame_buf;
                let socket = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;

                let mut records = Queue::new();
                let record = Self::fetch_record(socket, frame_buf, key_schedule).await?;
                Self::decrypt_record(key_schedule, &mut records, record)?;

                let socket = &mut self.delegate;
                let mut state = Some(state);
                while let Some(record) = records.dequeue() {
                    let next_state = match state.take().unwrap() {
                        State::ServerCert => match record {
                            ServerRecord::Handshake(handshake) => match handshake {
                                ServerHandshake::EncryptedExtensions(_) => Ok(State::ServerCert),
                                ServerHandshake::Certificate(_) => Ok(State::ServerCert),
                                ServerHandshake::CertificateVerify(_) => Ok(State::ServerFinished),
                                ServerHandshake::CertificateRequest(request) => {
                                    // TODO: Support supplying client cert if we have one
                                    let mut buf = [0; 16384];
                                    let handshake = ClientHandshake::ClientCert(Certificate::new());
                                    let record: ClientRecord<'a, 'm, RNG, CipherSuite> =
                                        ClientRecord::EncryptedHandshake(handshake);
                                    let (len, range) = record.encode(&mut buf[..], |buf| {
                                        Self::encrypt(key_schedule, buf)
                                    })?;

                                    if let Some(range) = range {
                                        Digest::update(key_schedule.transcript_hash(), &buf[range]);
                                    }

                                    socket.write(&buf[..len]).await?;

                                    key_schedule.increment_write_counter();
                                    Ok(State::ServerCert)
                                }
                                e => {
                                    info!("GOT INVALID HANDSHAKE: {:?}", e);
                                    Err(TlsError::InvalidHandshake)
                                }
                            },
                            ServerRecord::ChangeCipherSpec(_) => Ok(State::ServerCert),
                            _ => Err(TlsError::InvalidRecord),
                        },
                        State::ServerFinished => match record {
                            ServerRecord::Handshake(handshake) => match handshake {
                                ServerHandshake::Finished(finished) => {
                                    info!("************* Finished");
                                    let verified =
                                        key_schedule.verify_server_finished(&finished)?;
                                    if verified {
                                        debug!("server verified {}", verified);
                                        Ok(State::ClientFinished)
                                    } else {
                                        Err(TlsError::InvalidSignature)
                                    }
                                }
                                _ => Err(TlsError::InvalidHandshake),
                            },
                            _ => Err(TlsError::InvalidRecord),
                        },
                        state => Ok(state),
                    }?;
                    //info!("State {:?} -> {:?}", &self.state, &next_state);
                    state.replace(next_state);
                }
                Ok(state.unwrap())
            }
        }
    }

    pub async fn write<'m>(&mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
        if let Some(State::ApplicationData) = self.state {
            let mut wp = 0;
            let mut remaining = buf.len();
            while remaining > 0 {
                let to_write = core::cmp::min(remaining, FRAME_MTU);
                info!("Writing {} bytes", buf.len());
                let record: ClientRecord<'a, 'm, RNG, CipherSuite> =
                    ClientRecord::ApplicationData(&buf[wp..to_write]);
                self.transmit(&record).await?;
                wp += to_write;
                remaining -= to_write;
            }

            Ok(buf.len())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    pub async fn read<'m>(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>
    where
        'a: 'm,
    {
        if let Some(State::ApplicationData) = self.state {
            let mut remaining = buf.len();
            while remaining == buf.len() {
                let rx_buf = &mut self.frame_buf[..];
                let socket = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                let record = Self::fetch_record(socket, rx_buf, key_schedule).await?;
                let mut records = Queue::new();
                Self::decrypt_record(key_schedule, &mut records, record)?;
                while let Some(record) = records.dequeue() {
                    match record {
                        ServerRecord::ApplicationData(ApplicationData { header: _, data }) => {
                            info!("Got application data record");
                            if buf.len() < data.len() {
                                warn!("Passed buffer is too small");
                                Err(TlsError::EncodeError)
                            } else {
                                let to_copy = core::cmp::min(data.len(), buf.len());
                                // TODO Need to buffer data not consumed
                                log::info!("Got {} bytes to copy", to_copy);
                                buf[..to_copy].copy_from_slice(&data.as_slice()[..to_copy]);
                                remaining -= to_copy;
                                Ok(())
                            }
                        }
                        ServerRecord::Alert(alert) => {
                            error!("ALERT record! {:?}", alert);
                            Err(TlsError::InternalError)
                        }
                        ServerRecord::ChangeCipherSpec(_) => {
                            error!("Unexpected change cipher spec");
                            Err(TlsError::InternalError)
                        }
                        r => {
                            unimplemented!()
                        }
                    }?;
                }
            }
            Ok(buf.len() - remaining)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    pub fn delegate_socket(&mut self) -> &mut Socket {
        &mut self.delegate
    }
}
