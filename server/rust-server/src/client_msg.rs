//! Parser for client WebSocket FlatBuffer messages.
//!
//! All client messages share an outer wrapper:
//!   table Wrapper { type: uint32 (id:0); payload: [ubyte] (id:1); }
//!
//! The payload is a nested FlatBuffer whose schema depends on `type`.

use anyhow::{Context, Result};

/// Parsed client message.
#[derive(Debug)]
pub enum ClientMsg {
    /// type=0: Client init, sends steam_id
    Init { steam_id: String },
    /// type=10: Client acknowledges config entry
    ConfigAck { entry_id: u32 },
    /// type=3: Create a new log entry (script/config)
    CreateEntry {
        name: String,
        /// 1 = Script, 0 = Config
        entry_type: u32,
        /// Total entry count expected (including this new one)
        expected_count: u32,
    },
    /// type=1: Update an existing log entry
    UpdateEntry {
        entry_id: u32,
        entry_type: u32,
        content: Option<String>,
        name: Option<String>,
        timestamp: Option<u32>,
    },
    /// Unknown message type
    Unknown { msg_type: u32 },
}

pub fn parse(data: &[u8]) -> Result<ClientMsg> {
    let outer = parse_outer(data).context("parse outer wrapper")?;
    match outer.msg_type {
        0 => {
            let inner = Table::parse(outer.payload)?;
            let steam_id = inner.read_string(0).unwrap_or_default();
            Ok(ClientMsg::Init { steam_id })
        }
        10 => {
            let inner = Table::parse(outer.payload)?;
            let entry_id = inner.read_u32(0).unwrap_or(0);
            Ok(ClientMsg::ConfigAck { entry_id })
        }
        3 => {
            let inner = Table::parse(outer.payload)?;
            let name = inner.read_string(0).unwrap_or_default();
            let entry_type = inner.read_u32(1).unwrap_or(0);
            let expected_count = inner.read_u32(2).unwrap_or(0);
            Ok(ClientMsg::CreateEntry {
                name,
                entry_type,
                expected_count,
            })
        }
        1 => {
            let inner = Table::parse(outer.payload)?;
            let entry_id = inner.read_u32(0).unwrap_or(0);
            let entry_type = inner.read_u32(1).unwrap_or(0);
            let content = inner.read_string(2);
            let name = inner.read_string(3);
            let timestamp = inner.read_u32(4);
            Ok(ClientMsg::UpdateEntry {
                entry_id,
                entry_type,
                content,
                name,
                timestamp,
            })
        }
        t => Ok(ClientMsg::Unknown { msg_type: t }),
    }
}

struct OuterMsg<'a> {
    msg_type: u32,
    payload: &'a [u8],
}

fn parse_outer(buf: &[u8]) -> Result<OuterMsg<'_>> {
    anyhow::ensure!(buf.len() >= 8, "outer too short: {} bytes", buf.len());
    let tbl = Table::parse(buf)?;

    // field[0] = type (u32), field[1] = payload ([ubyte] vector)
    let msg_type = tbl.read_u32(0).unwrap_or(0);
    let payload_field = tbl.field_offset(1);

    let payload = if let Some(foff) = payload_field {
        let abs = tbl.root_pos + foff;
        anyhow::ensure!(abs + 4 <= buf.len(), "payload offset out of bounds");
        let rel = read_u32(buf, abs) as usize;
        let vec_pos = abs + rel;
        anyhow::ensure!(vec_pos + 4 <= buf.len(), "payload vector out of bounds");
        let vec_len = read_u32(buf, vec_pos) as usize;
        anyhow::ensure!(
            vec_pos + 4 + vec_len <= buf.len(),
            "payload data out of bounds"
        );
        &buf[vec_pos + 4..vec_pos + 4 + vec_len]
    } else {
        &[]
    };

    Ok(OuterMsg { msg_type, payload })
}

/// Minimal FlatBuffer table reader.
struct Table<'a> {
    buf: &'a [u8],
    root_pos: usize,
    vt_pos: usize,
    vt_size: usize,
}

impl<'a> Table<'a> {
    fn parse(buf: &'a [u8]) -> Result<Self> {
        anyhow::ensure!(buf.len() >= 4, "table too short");
        let root_off = read_u32(buf, 0) as usize;
        anyhow::ensure!(root_off + 4 <= buf.len(), "root offset out of bounds");
        let soff = read_i32(buf, root_off);
        let vt_pos = (root_off as i64 - soff as i64) as usize;
        anyhow::ensure!(vt_pos + 4 <= buf.len(), "vtable out of bounds");
        let vt_size = read_u16(buf, vt_pos) as usize;
        anyhow::ensure!(
            vt_pos + vt_size <= buf.len(),
            "vtable extends out of bounds"
        );
        Ok(Table {
            buf,
            root_pos: root_off,
            vt_pos,
            vt_size,
        })
    }

    fn num_fields(&self) -> usize {
        (self.vt_size - 4) / 2
    }

    fn field_offset(&self, field_id: usize) -> Option<usize> {
        if field_id >= self.num_fields() {
            return None;
        }
        let foff = read_u16(self.buf, self.vt_pos + 4 + field_id * 2) as usize;
        if foff == 0 { None } else { Some(foff) }
    }

    fn read_u32(&self, field_id: usize) -> Option<u32> {
        let foff = self.field_offset(field_id)?;
        let pos = self.root_pos + foff;
        if pos + 4 > self.buf.len() {
            return None;
        }
        Some(read_u32(self.buf, pos))
    }

    fn read_string(&self, field_id: usize) -> Option<String> {
        let foff = self.field_offset(field_id)?;
        let pos = self.root_pos + foff;
        if pos + 4 > self.buf.len() {
            return None;
        }
        let rel = read_u32(self.buf, pos) as usize;
        let str_pos = pos + rel;
        if str_pos + 4 > self.buf.len() {
            return None;
        }
        let len = read_u32(self.buf, str_pos) as usize;
        if str_pos + 4 + len > self.buf.len() {
            return None;
        }
        std::str::from_utf8(&self.buf[str_pos + 4..str_pos + 4 + len])
            .ok()
            .map(|s| s.to_string())
    }
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}
