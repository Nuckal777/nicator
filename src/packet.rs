use std::convert::TryInto;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Packet {
    Lock,
    Unlock {
        passphrase: String,
        timeout: u64,
    },
    Result {
        success: bool,
        message: String,
    },
    Store {
        credential: crate::store::Credential,
    },
    Get {
        credential: crate::store::Credential,
    },
    Erase {
        credential: crate::store::Credential,
    },
}

pub fn parse<R: std::io::Read>(reader: &mut R) -> Result<Packet, crate::Error> {
    let packet_size = reader.read_u16::<LittleEndian>()?;
    let mut data_buf = vec![0_u8; packet_size.into()];
    reader.read_exact(&mut data_buf)?;
    let packet: Packet = bincode::deserialize(&data_buf)?;
    Ok(packet)
}

pub fn write<W: std::io::Write>(writer: &mut W, packet: &Packet) -> Result<(), crate::Error> {
    let data = bincode::serialize(packet)?;
    writer.write_u16::<LittleEndian>(
        data.len()
            .try_into()
            .map_err(|_| crate::Error::Conversion)?,
    )?;
    writer.write_all(&data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    #[test]
    fn write_parse() -> Result<(), crate::Error> {
        let mut data = Vec::<u8>::new();
        super::write(&mut Cursor::new(&mut data), &super::Packet::Unlock{
            passphrase: "pass".to_string(),
            timeout: 678,
        })?;
        let result = super::parse(&mut Cursor::new(&data))?;
        match result {
            super::Packet::Unlock{passphrase, timeout} => {
                assert_eq!(passphrase, "pass");
                assert_eq!(timeout, 678);
            },
            _ => panic!("Packet type does not macth"),
        }
        Ok(())
    }
}
