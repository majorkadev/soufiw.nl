//! Custom FlatBuffer builder matching Google C++ FlatBuffers binary layout.
//!
//! Fields are written **directly to the output buffer** (no data stack), so
//! objects created between `start_table`/`end_table` (like strings) become part
//! of the table's contiguous byte range — matching the C++ builder exactly.
//!
//! - Inline vtable placement (vtable immediately before its table).
//! - Vtable deduplication via full byte comparison.

/// Opaque reference to a position in the output buffer.
/// Stores the `used_space()` at the time the object was created.
#[derive(Clone, Copy)]
pub struct Ref(u32);

impl Ref {
    /// Create a placeholder ref (will be overwritten before use).
    pub fn dummy() -> Self { Ref(0) }
}

pub struct FlatccBuilder {
    /// Output buffer — grows backward from the end.
    buf: Vec<u8>,
    /// Current write head (byte index into `buf`). Data lives in `buf[head..]`.
    head: usize,
    /// Buffer-wide minimum alignment (tracked across all emissions).
    min_align: usize,
    /// Whether to write default-valued scalars (force_defaults mode).
    force_defaults: bool,

    // --- Current table construction ---
    /// `used_space()` at the time `start_table()` was called.
    table_start: usize,
    /// Number of vtable slots for the current table.
    field_count: usize,
    /// Tracked fields: `(field_id, used_space_after_push)`.
    fields: Vec<(usize, usize)>,
    /// Whether we are currently inside a `start_table`/`end_table` pair.
    in_table: bool,

    // --- Vtable deduplication ---
    /// `used_space` positions of all written vtables (for dedup lookups).
    vtables: Vec<usize>,
}

impl FlatccBuilder {
    pub fn new() -> Self {
        let initial_cap = 1024;
        Self {
            buf: vec![0u8; initial_cap],
            head: initial_cap,
            min_align: 1,
            force_defaults: false,
            table_start: 0,
            field_count: 0,
            fields: Vec::new(),
            in_table: false,
            vtables: Vec::new(),
        }
    }

    pub fn force_defaults(&mut self, v: bool) {
        self.force_defaults = v;
    }

    // ---------------------------------------------------------------
    // Buffer management
    // ---------------------------------------------------------------

    #[inline]
    fn used_space(&self) -> usize {
        self.buf.len() - self.head
    }

    fn grow(&mut self, additional: usize) {
        if self.head >= additional {
            return;
        }
        let needed = additional - self.head;
        let new_cap = (self.buf.len() + needed).next_power_of_two();
        let grow_by = new_cap - self.buf.len();
        let mut new_buf = vec![0u8; new_cap];
        new_buf[grow_by + self.head..].copy_from_slice(&self.buf[self.head..]);
        self.head += grow_by;
        self.buf = new_buf;
    }

    fn align(&mut self, align: usize) {
        let used = self.used_space();
        let pad = (align - (used % align)) % align;
        if pad > 0 {
            self.grow(pad);
            self.head -= pad;
        }
        if align > self.min_align {
            self.min_align = align;
        }
    }

    fn push_bytes(&mut self, data: &[u8]) {
        self.grow(data.len());
        self.head -= data.len();
        self.buf[self.head..self.head + data.len()].copy_from_slice(data);
    }

    fn push_u32(&mut self, v: u32) {
        self.push_bytes(&v.to_le_bytes());
    }

    fn write_i32_at(&mut self, abs_index: usize, v: i32) {
        self.buf[abs_index..abs_index + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Push N zero bytes into the output buffer (for reproducing alignment gaps).
    pub fn push_zeros(&mut self, n: usize) {
        self.grow(n);
        self.head -= n;
        // buf is already zeroed from allocation
    }

    // ---------------------------------------------------------------
    // Strings
    // ---------------------------------------------------------------

    /// Create a null-terminated string with u32 length prefix.
    /// Layout (forward): `[len:u32] [bytes...] [0x00] [padding]`
    /// Padding matches C++ `PreAlign(len+1, 4)`: pad so `(used + len + 1)` is 4-aligned.
    pub fn create_string(&mut self, s: &str) -> Ref {
        let bytes = s.as_bytes();
        let len = bytes.len();
        // C++ PreAlign: pad so (used_space + len + 1) is 4-aligned.
        let data_len = len + 1; // data bytes + null terminator
        let pad = (4 - ((self.used_space() + data_len) % 4)) % 4;
        if 4 > self.min_align {
            self.min_align = 4;
        }
        let total = pad + data_len + 4; // padding + data + null + count
        self.grow(total);
        self.head -= pad; // trailing padding (appears after null in forward buffer)
        self.head -= 1; // null terminator
        self.head -= len;
        self.buf[self.head..self.head + len].copy_from_slice(bytes);
        self.head -= 4; // length prefix
        self.buf[self.head..self.head + 4].copy_from_slice(&(len as u32).to_le_bytes());

        Ref(self.used_space() as u32)
    }

    // ---------------------------------------------------------------
    // Vectors
    // ---------------------------------------------------------------

    /// Create a byte vector: `[count:u32] [data...] [padding]`
    /// Padding matches C++ `PreAlign(len, 4)`: pad so `(used + len)` is 4-aligned.
    pub fn create_vector_u8(&mut self, data: &[u8]) -> Ref {
        let len = data.len();
        // C++ PreAlign: pad so (used_space + len) is 4-aligned.
        let pad = (4 - ((self.used_space() + len) % 4)) % 4;
        if 4 > self.min_align {
            self.min_align = 4;
        }
        let total = pad + len + 4;
        self.grow(total);
        self.head -= pad;
        self.head -= len;
        self.buf[self.head..self.head + len].copy_from_slice(data);
        self.head -= 4;
        self.buf[self.head..self.head + 4].copy_from_slice(&(len as u32).to_le_bytes());

        Ref(self.used_space() as u32)
    }

    /// Create a vector of offsets: `[count:u32] [offset0:u32] [offset1:u32] ...`
    pub fn create_vector_offsets(&mut self, refs: &[Ref]) -> Ref {
        let count = refs.len();
        let data_size = count * 4;
        // data_size is always a multiple of 4, so PreAlign(data_size, 4) = align(4).
        let pad = (4 - ((self.used_space() + data_size) % 4)) % 4;
        if 4 > self.min_align {
            self.min_align = 4;
        }
        let total = pad + data_size + 4;

        self.grow(total);
        self.head -= pad;
        self.head -= data_size;
        let data_start = self.head;
        self.head -= 4;
        self.buf[self.head..self.head + 4].copy_from_slice(&(count as u32).to_le_bytes());

        for (i, r) in refs.iter().enumerate() {
            let slot_used_space = (self.buf.len() - data_start - i * 4) as u32;
            let rel = slot_used_space - r.0;
            self.buf[data_start + i * 4..data_start + i * 4 + 4]
                .copy_from_slice(&rel.to_le_bytes());
        }

        Ref(self.used_space() as u32)
    }

    // ---------------------------------------------------------------
    // Tables — fields written directly to output buffer
    // ---------------------------------------------------------------

    /// Begin constructing a table with up to `field_count` fields.
    pub fn start_table(&mut self, field_count: usize) {
        self.in_table = true;
        self.table_start = self.used_space();
        self.field_count = field_count;
        self.fields.clear();
    }

    /// Add a u32 scalar field to the current table.
    pub fn table_add_u32(&mut self, id: usize, value: u32, default: u32) {
        if !self.force_defaults && value == default {
            return;
        }
        self.align(4);
        self.push_u32(value);
        self.fields.push((id, self.used_space()));
    }

    /// Add an offset field (pointing to a string, vector, or table).
    pub fn table_add_offset(&mut self, id: usize, r: Ref) {
        self.align(4);
        // Relative offset: distance from this field's position to the target.
        // rel = used_space_after_align + 4 - r.0
        //     = (field_forward_pos is at total - used - 4, target at total - r.0)
        //     = target_forward - field_forward = used + 4 - r.0
        let rel = self.used_space() as u32 + 4 - r.0;
        self.push_u32(rel);
        self.fields.push((id, self.used_space()));
    }

    /// Finish the current table. Emits soffset + vtable to the output buffer.
    pub fn end_table(&mut self) -> Ref {
        // Push soffset placeholder (4 bytes) — this is the table's "start" in the
        // forward buffer. All field offsets in the vtable are relative to this point.
        self.align(4);
        self.push_u32(0); // placeholder
        let vt_loc = self.used_space();
        let table_abs = self.head; // absolute position of soffset in buf

        let table_size = vt_loc - self.table_start;

        // Build vtable: [vt_size:u16] [table_size:u16] [field0:u16] [field1:u16] ...
        let vt_header = 4;
        let vt_full_size = vt_header + self.field_count * 2;
        let mut vtable = vec![0u8; vt_full_size];
        // table_size header filled below after trimming
        vtable[2..4].copy_from_slice(&(table_size as u16).to_le_bytes());

        for &(field_id, field_used) in &self.fields {
            let field_off = (vt_loc - field_used) as u16;
            vtable[vt_header + field_id * 2..vt_header + field_id * 2 + 2]
                .copy_from_slice(&field_off.to_le_bytes());
        }

        // Trim trailing zero slots from vtable (matching C++ builder behavior).
        // The C++ builder removes trailing zero voffset entries to minimize vtable size.
        let mut vt_size = vt_full_size;
        while vt_size > vt_header {
            let slot_off = vt_size - 2;
            if vtable[slot_off] != 0 || vtable[slot_off + 1] != 0 {
                break;
            }
            vt_size -= 2;
        }
        vtable.truncate(vt_size);
        vtable[0..2].copy_from_slice(&(vt_size as u16).to_le_bytes());

        // Vtable deduplication.
        let mut existing_vtable_used = None;
        for &vt_pos in &self.vtables {
            let vt_abs = self.buf.len() - vt_pos;
            if vt_abs + 2 > self.buf.len() {
                continue;
            }
            let existing_size =
                u16::from_le_bytes([self.buf[vt_abs], self.buf[vt_abs + 1]]) as usize;
            if existing_size != vt_size {
                continue;
            }
            if vt_abs + existing_size > self.buf.len() {
                continue;
            }
            if self.buf[vt_abs..vt_abs + existing_size] == vtable[..] {
                existing_vtable_used = Some(vt_pos);
                break;
            }
        }

        let soffset: i32;
        if let Some(existing_used) = existing_vtable_used {
            let vtable_abs = self.buf.len() - existing_used;
            soffset = table_abs as i32 - vtable_abs as i32;
        } else {
            // Emit new vtable inline, immediately before the table.
            self.push_bytes(&vtable);
            let vtable_abs = self.head;
            self.vtables.push(self.buf.len() - vtable_abs);
            soffset = table_abs as i32 - vtable_abs as i32;
        }

        // Patch soffset.
        self.write_i32_at(table_abs, soffset);
        self.in_table = false;

        Ref(vt_loc as u32)
    }

    /// Finish the buffer: prepend root offset, return final bytes.
    pub fn finish_minimal(mut self, root: Ref) -> Vec<u8> {
        let align = self.min_align.max(4);
        let used = self.used_space();
        let total = 4 + used;
        let padded_total = (total + align - 1) & !(align - 1);
        let pad = padded_total - total;
        if pad > 0 {
            self.grow(pad);
            self.head -= pad;
        }
        // Root offset = distance from byte 0 to the root table.
        let root_abs = self.buf.len() - root.0 as usize;
        let root_final_pos = root_abs - self.head + 4;
        self.push_u32(root_final_pos as u32);

        self.buf[self.head..].to_vec()
    }

    pub fn finish(self, root: Ref) -> Vec<u8> {
        self.finish_minimal(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_layout() {
        let mut b = FlatccBuilder::new();
        let _r = b.create_string("hello");
        let used = b.used_space();
        assert_eq!(used, 12);
        let data = &b.buf[b.head..];
        assert_eq!(&data[0..4], &[5, 0, 0, 0]);
        assert_eq!(&data[4..9], b"hello");
        assert_eq!(data[9], 0);
        assert_eq!(&data[10..12], &[0, 0]);
    }

    #[test]
    fn test_vector_u8_layout() {
        let mut b = FlatccBuilder::new();
        let _r = b.create_vector_u8(&[1, 2, 3]);
        let used = b.used_space();
        assert_eq!(used, 8);
        let data = &b.buf[b.head..];
        assert_eq!(&data[0..4], &[3, 0, 0, 0]);
        assert_eq!(&data[4..7], &[1, 2, 3]);
        assert_eq!(data[7], 0);
    }

    #[test]
    fn test_simple_table() {
        let mut b = FlatccBuilder::new();
        b.start_table(2);
        b.table_add_u32(0, 42, 0);
        b.table_add_u32(1, 99, 0);
        let root = b.end_table();
        let buf = b.finish_minimal(root);

        let root_off = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let soffset = i32::from_le_bytes(buf[root_off..root_off + 4].try_into().unwrap());
        let vtable_pos = (root_off as i32 - soffset) as usize;
        let vt_size = u16::from_le_bytes(buf[vtable_pos..vtable_pos + 2].try_into().unwrap());
        let tbl_size = u16::from_le_bytes(buf[vtable_pos + 2..vtable_pos + 4].try_into().unwrap());
        assert_eq!(vt_size, 8);
        assert_eq!(tbl_size, 12); // 4 soffset + 4 field0 + 4 field1

        let field0_off =
            u16::from_le_bytes(buf[vtable_pos + 4..vtable_pos + 6].try_into().unwrap());
        let field1_off =
            u16::from_le_bytes(buf[vtable_pos + 6..vtable_pos + 8].try_into().unwrap());
        let val0 = u32::from_le_bytes(
            buf[root_off + field0_off as usize..root_off + field0_off as usize + 4]
                .try_into()
                .unwrap(),
        );
        let val1 = u32::from_le_bytes(
            buf[root_off + field1_off as usize..root_off + field1_off as usize + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(val0, 42);
        assert_eq!(val1, 99);
    }

    #[test]
    fn test_table_with_string_offset() {
        let mut b = FlatccBuilder::new();
        let s = b.create_string("test");
        b.start_table(1);
        b.table_add_offset(0, s);
        let root = b.end_table();
        let buf = b.finish_minimal(root);

        let root_off = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let soffset = i32::from_le_bytes(buf[root_off..root_off + 4].try_into().unwrap());
        let vtable_pos = (root_off as i32 - soffset) as usize;
        let field0_off =
            u16::from_le_bytes(buf[vtable_pos + 4..vtable_pos + 6].try_into().unwrap()) as usize;
        let offset_val = u32::from_le_bytes(
            buf[root_off + field0_off..root_off + field0_off + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let string_pos = root_off + field0_off + offset_val;
        let str_len =
            u32::from_le_bytes(buf[string_pos..string_pos + 4].try_into().unwrap()) as usize;
        assert_eq!(str_len, 4);
        assert_eq!(&buf[string_pos + 4..string_pos + 8], b"test");
    }

    #[test]
    fn test_inline_string_in_table() {
        // create_string between start_table/end_table — string becomes part of
        // the table's byte range, inflating table_size.
        let mut b = FlatccBuilder::new();
        b.start_table(2);
        b.table_add_u32(0, 1, 0);
        let s = b.create_string("inline"); // 4+6+1+1pad = 12 bytes
        b.table_add_offset(1, s);
        let root = b.end_table();
        let buf = b.finish_minimal(root);

        let root_off = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let soffset = i32::from_le_bytes(buf[root_off..root_off + 4].try_into().unwrap());
        let vtable_pos = (root_off as i32 - soffset) as usize;
        let tbl_size = u16::from_le_bytes(buf[vtable_pos + 2..vtable_pos + 4].try_into().unwrap());
        // table_size = 4 (soffset) + 4 (offset field) + 12 (inline string) + 4 (u32 field) = 24
        assert_eq!(tbl_size, 24);

        // Verify fields parse correctly.
        let field0_off =
            u16::from_le_bytes(buf[vtable_pos + 4..vtable_pos + 6].try_into().unwrap()) as usize;
        let field1_off =
            u16::from_le_bytes(buf[vtable_pos + 6..vtable_pos + 8].try_into().unwrap()) as usize;
        let val0 = u32::from_le_bytes(
            buf[root_off + field0_off..root_off + field0_off + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(val0, 1);
        let offset_val = u32::from_le_bytes(
            buf[root_off + field1_off..root_off + field1_off + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let string_pos = root_off + field1_off + offset_val;
        let str_len =
            u32::from_le_bytes(buf[string_pos..string_pos + 4].try_into().unwrap()) as usize;
        assert_eq!(str_len, 6);
        assert_eq!(&buf[string_pos + 4..string_pos + 10], b"inline");
    }

    #[test]
    fn test_vtable_dedup() {
        // Use 2-field tables so total size (vtable 8 + table 12 = 20) is 4-aligned.
        // This ensures both tables start at the same alignment and produce identical vtables.
        let mut b = FlatccBuilder::new();
        b.start_table(2);
        b.table_add_u32(0, 10, 0);
        b.table_add_u32(1, 20, 0);
        let _t1 = b.end_table();
        b.start_table(2);
        b.table_add_u32(0, 30, 0);
        b.table_add_u32(1, 40, 0);
        let _t2 = b.end_table();
        assert_eq!(b.vtables.len(), 1);
    }

    #[test]
    fn test_vector_of_offsets() {
        let mut b = FlatccBuilder::new();
        let s1 = b.create_string("aaa");
        let s2 = b.create_string("bbb");
        let vec = b.create_vector_offsets(&[s1, s2]);
        b.start_table(1);
        b.table_add_offset(0, vec);
        let root = b.end_table();
        let buf = b.finish_minimal(root);

        let root_off = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let soffset = i32::from_le_bytes(buf[root_off..root_off + 4].try_into().unwrap());
        let vtable_pos = (root_off as i32 - soffset) as usize;
        let field0_off =
            u16::from_le_bytes(buf[vtable_pos + 4..vtable_pos + 6].try_into().unwrap()) as usize;
        let vec_rel = u32::from_le_bytes(
            buf[root_off + field0_off..root_off + field0_off + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let vec_pos = root_off + field0_off + vec_rel;
        let count = u32::from_le_bytes(buf[vec_pos..vec_pos + 4].try_into().unwrap()) as usize;
        assert_eq!(count, 2);

        let off0 = u32::from_le_bytes(buf[vec_pos + 4..vec_pos + 8].try_into().unwrap()) as usize;
        let s1_pos = vec_pos + 4 + off0;
        let s1_len = u32::from_le_bytes(buf[s1_pos..s1_pos + 4].try_into().unwrap()) as usize;
        assert_eq!(s1_len, 3);
        assert_eq!(&buf[s1_pos + 4..s1_pos + 7], b"aaa");

        let off1 =
            u32::from_le_bytes(buf[vec_pos + 8..vec_pos + 12].try_into().unwrap()) as usize;
        let s2_pos = vec_pos + 8 + off1;
        let s2_len = u32::from_le_bytes(buf[s2_pos..s2_pos + 4].try_into().unwrap()) as usize;
        assert_eq!(s2_len, 3);
        assert_eq!(&buf[s2_pos + 4..s2_pos + 7], b"bbb");
    }
}
