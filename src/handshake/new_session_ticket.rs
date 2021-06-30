use heapless::{consts::*, Vec};

use crate::extensions::server::ServerExtension;
use crate::parse_buffer::ParseBuffer;
use crate::TlsError;

#[derive(Debug)]
pub struct NewSessionTicket<'a> {
    lifetime: u32,
    age_add: u32,
    nonce: &'a [u8],
    ticket: &'a [u8],
    extensions: Vec<ServerExtension<'a>, U16>,
}

impl<'a> NewSessionTicket<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<NewSessionTicket<'a>, TlsError> {
        let lifetime = buf.read_u32()?;
        let age_add = buf.read_u32()?;

        let nonce_length = buf.read_u8()?;
        let nonce = buf
            .slice(nonce_length as usize)
            .map_err(|_| TlsError::InvalidNonceLength)?;

        let ticket_length = buf.read_u16()?;
        let ticket = buf
            .slice(ticket_length as usize)
            .map_err(|_| TlsError::InvalidTicketLength)?;

        let _extensions_length = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;
        let extensions = ServerExtension::parse_vector(buf)?;

        Ok(Self {
            lifetime,
            age_add,
            nonce: nonce.as_slice(),
            ticket: ticket.as_slice(),
            extensions,
        })
    }
}
