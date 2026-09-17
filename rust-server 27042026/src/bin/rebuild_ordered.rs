//! Rebuild FlatBuffer using FlatccBuilder and compare byte-for-byte with original.
//! Usage: cargo run --bin rebuild_ordered

use nl_parser::flatcc_builder::{FlatccBuilder, Ref};
use nl_parser::module::{LogEntry, Module, serialize_translations_json};
use nl_parser::pipeline;

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}
fn read_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Walk a table at `tbl_pos` (absolute in buf), print all vtable slots and values
fn dump_table(buf: &[u8], tbl_pos: usize, label: &str) {
    let soff = read_i32(buf, tbl_pos);
    let vt_pos = (tbl_pos as i32 - soff) as usize;
    let vt_size = read_u16(buf, vt_pos) as usize;
    let tbl_size = read_u16(buf, vt_pos + 2);
    let num_fields = (vt_size - 4) / 2;
    print!(
        "  {}: vt_size={}, tbl_size={}, fields:",
        label, vt_size, tbl_size
    );
    for i in 0..num_fields {
        let foff = read_u16(buf, vt_pos + 4 + i * 2);
        if foff != 0 {
            let fpos = tbl_pos + foff as usize;
            let val = read_u32(buf, fpos);
            print!(" [{}]=off{}(0x{:x})", i, foff, val);
        }
    }
    println!();
}

fn main() {
    let module_bin = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../data/module.bin"));
    let original = pipeline::load_module(module_bin).expect("decrypt/decompress");

    // === DEEP ANALYSIS OF ORIGINAL BINARY ===
    // Check ALL sub-tables for unknown fields with data
    let inner_start: usize = 28;
    let buf = original.as_slice();
    let root_off = read_u32(buf, inner_start) as usize;
    let root_pos = inner_start + root_off;

    println!("=== ORIGINAL: ROOT TABLE ===");
    dump_table(buf, root_pos, "root");

    // Walk config_log entries
    let soff = read_i32(buf, root_pos);
    let vt_pos = (root_pos as i32 - soff) as usize;
    let cfglog_foff = read_u16(buf, vt_pos + 4 + 4 * 2) as usize; // field 4
    if cfglog_foff != 0 {
        let vec_rel = read_u32(buf, root_pos + cfglog_foff) as usize;
        let vec_pos = root_pos + cfglog_foff + vec_rel;
        let count = read_u32(buf, vec_pos) as usize;
        println!("\n=== CONFIG_LOG ({} entries) ===", count);
        for i in 0..count {
            let off_rel = read_u32(buf, vec_pos + 4 + i * 4) as usize;
            let entry_pos = vec_pos + 4 + i * 4 + off_rel;
            dump_table(buf, entry_pos, &format!("config[{}]", i));
        }
    }

    // Walk script_log entries
    let scrlog_foff = read_u16(buf, vt_pos + 4 + 5 * 2) as usize; // field 5
    if scrlog_foff != 0 {
        let vec_rel = read_u32(buf, root_pos + scrlog_foff) as usize;
        let vec_pos = root_pos + scrlog_foff + vec_rel;
        let count = read_u32(buf, vec_pos) as usize;
        println!("\n=== SCRIPT_LOG ({} entries) ===", count);
        for i in 0..count {
            let off_rel = read_u32(buf, vec_pos + 4 + i * 4) as usize;
            let entry_pos = vec_pos + 4 + i * 4 + off_rel;
            dump_table(buf, entry_pos, &format!("script[{}]", i));
        }
    }

    // Walk language tables
    let lang_foff = read_u16(buf, vt_pos + 4 + 7 * 2) as usize; // field 7
    if lang_foff != 0 {
        let vec_rel = read_u32(buf, root_pos + lang_foff) as usize;
        let vec_pos = root_pos + lang_foff + vec_rel;
        let count = read_u32(buf, vec_pos) as usize;
        println!("\n=== LANGUAGES ({} entries) ===", count);
        for i in 0..count {
            let off_rel = read_u32(buf, vec_pos + 4 + i * 4) as usize;
            let lang_pos = vec_pos + 4 + i * 4 + off_rel;
            dump_table(buf, lang_pos, &format!("lang[{}]", i));
        }
    }

    // === Compare raw translations strings with re-serialized versions ===
    println!("\n=== TRANSLATIONS STRING COMPARISON ===");
    {
        use nl_parser::flatbuf::nl;
        let wrapper = nl::root_as_module_wrapper(&original).unwrap();
        let md = wrapper.payload_nested_flatbuffer().unwrap();
        let langs = md.languages().unwrap();
        let mut total_orig_str_bytes: usize = 0;
        let mut total_reserialized_bytes: usize = 0;
        for i in 0..langs.len() {
            let l = langs.get(i);
            let code = l.code().unwrap_or("?");
            if let Some(t) = l.translations() {
                let orig_bytes = t.bytes();
                total_orig_str_bytes += orig_bytes.len();
                // Re-serialize through our pipeline
                let value: serde_json::Value = serde_json::from_slice(orig_bytes).unwrap();
                let reserialized = serialize_translations_json(&value).unwrap();
                total_reserialized_bytes += reserialized.len();
                let diff = orig_bytes.len() as i64 - reserialized.len() as i64;
                println!(
                    "  lang[{}] '{}': orig_translations={} reserialized={} diff={}",
                    i,
                    code,
                    orig_bytes.len(),
                    reserialized.len(),
                    diff
                );
                if orig_bytes != reserialized.as_slice() {
                    // Find first diff
                    for j in 0..orig_bytes.len().max(reserialized.len()) {
                        let a = orig_bytes.get(j);
                        let b = reserialized.get(j);
                        if a != b {
                            println!(
                                "    first diff at byte {}: orig={:?} reser={:?}",
                                j,
                                a.map(|v| format!("0x{:02x} '{}'", v, char::from(*v))),
                                b.map(|v| format!("0x{:02x} '{}'", v, char::from(*v)))
                            );
                            // Show context
                            let start = j.saturating_sub(20);
                            let end = (j + 20).min(orig_bytes.len());
                            println!(
                                "    orig  context: {:?}",
                                std::str::from_utf8(&orig_bytes[start..end])
                                    .unwrap_or("(non-utf8)")
                            );
                            let end2 = (j + 20).min(reserialized.len());
                            println!(
                                "    reser context: {:?}",
                                std::str::from_utf8(&reserialized[start..end2])
                                    .unwrap_or("(non-utf8)")
                            );
                            break;
                        }
                    }
                }
            }
        }
        println!(
            "  Total translations: orig={} reserialized={} diff={}",
            total_orig_str_bytes,
            total_reserialized_bytes,
            total_orig_str_bytes as i64 - total_reserialized_bytes as i64
        );

        // Also compare ALL string lengths in the original
        println!("\n=== ALL ORIGINAL STRINGS ===");
        println!(
            "  author: '{}' ({})",
            md.author().unwrap_or(""),
            md.author().unwrap_or("").len()
        );
        println!(
            "  auth_token: '{}' ({})",
            md.auth_token().unwrap_or(""),
            md.auth_token().unwrap_or("").len()
        );
        let config_log = md.config_log().unwrap();
        for i in 0..config_log.len() {
            let e = config_log.get(i);
            println!(
                "  config[{}]: type='{}' ({}) author='{}' ({})",
                i,
                e.entry_type().unwrap_or(""),
                e.entry_type().unwrap_or("").len(),
                e.author().unwrap_or(""),
                e.author().unwrap_or("").len()
            );
        }
        let script_log = md.script_log().unwrap();
        for i in 0..script_log.len() {
            let e = script_log.get(i);
            println!(
                "  script[{}]: type='{}' ({}) author='{}' ({})",
                i,
                e.entry_type().unwrap_or(""),
                e.entry_type().unwrap_or("").len(),
                e.author().unwrap_or(""),
                e.author().unwrap_or("").len()
            );
        }
        for i in 0..langs.len() {
            let l = langs.get(i);
            println!(
                "  lang[{}]: code='{}' ({}) eng='{}' ({}) native='{}' ({}) trans={}",
                i,
                l.code().unwrap_or(""),
                l.code().unwrap_or("").len(),
                l.english_name().unwrap_or(""),
                l.english_name().unwrap_or("").len(),
                l.native_name().unwrap_or(""),
                l.native_name().unwrap_or("").len(),
                l.translations().map(|t| t.bytes().len()).unwrap_or(0)
            );
        }

        // Compute total string bytes including padding in original
        println!("\n=== SKIN DATA ===");
        println!(
            "  skin_data raw bytes: {}",
            md.skin_data().unwrap().bytes().len()
        );
        println!(
            "  extra_data raw bytes: {}",
            md.extra_data().map(|v| v.bytes().len()).unwrap_or(0)
        );
    }

    println!("\n=== REBUILD & COMPARE ===");
    let module = Module::from_flatbuffer(&original).expect("parse");
    let raw_skin = Module::extract_raw_skin_data(&original).expect("extract skin");

    let rebuilt = rebuild_correct_order(&module, &raw_skin).expect("rebuild");

    println!("Original: {} bytes", original.len());
    println!("Rebuilt:  {} bytes", rebuilt.len());

    let max = original.len().max(rebuilt.len());
    let mut diffs = 0;
    for i in 0..max {
        let a = original.get(i).copied();
        let b = rebuilt.get(i).copied();
        if a != b {
            diffs += 1;
        }
    }
    println!(
        "Differing bytes: {} / {} ({:.1}%)",
        diffs,
        max,
        diffs as f64 / max as f64 * 100.0
    );

    if diffs == 0 {
        println!("\n*** BYTE-IDENTICAL! ***");
    } else {
        // === END-ALIGNED comparison of INNER flatbuffers ===
        let inner_orig = &original[28..];
        let inner_rebuilt = &rebuilt[28..];
        println!(
            "\nInner FB sizes: orig={} rebuilt={} diff={}",
            inner_orig.len(),
            inner_rebuilt.len(),
            inner_orig.len() as i64 - inner_rebuilt.len() as i64
        );

        // Find how many bytes match from the end
        let mut end_match = 0;
        let o_len = inner_orig.len();
        let r_len = inner_rebuilt.len();
        while end_match < o_len.min(r_len) {
            if inner_orig[o_len - 1 - end_match] != inner_rebuilt[r_len - 1 - end_match] {
                break;
            }
            end_match += 1;
        }
        println!(
            "Bytes matching from end: {} (tail region starts at orig[{}], rebuilt[{}])",
            end_match,
            o_len - end_match,
            r_len - end_match
        );

        // Find first diff position in inner FB
        let mut first_diff = 0;
        while first_diff < o_len.min(r_len) && inner_orig[first_diff] == inner_rebuilt[first_diff] {
            first_diff += 1;
        }
        println!("First inner diff at: {}", first_diff);

        // The gap region in original: first_diff .. (o_len - end_match)
        // The gap region in rebuilt: first_diff .. (r_len - end_match)
        let orig_gap_end = o_len - end_match;
        let rebuilt_gap_end = r_len - end_match;
        println!(
            "Divergent region: orig[{}..{}] ({} bytes) vs rebuilt[{}..{}] ({} bytes)",
            first_diff,
            orig_gap_end,
            orig_gap_end - first_diff,
            first_diff,
            rebuilt_gap_end,
            rebuilt_gap_end - first_diff
        );
        println!(
            "Region size diff: {}",
            (orig_gap_end - first_diff) as i64 - (rebuilt_gap_end - first_diff) as i64
        );

        // Hex dump the divergent region boundaries
        println!(
            "\n--- ORIGINAL inner around first divergence [{}..{}] ---",
            first_diff,
            (first_diff + 64).min(orig_gap_end)
        );
        for i in first_diff..(first_diff + 64).min(o_len) {
            if (i - first_diff) % 16 == 0 {
                print!("  {:6}: ", i);
            }
            print!("{:02x} ", inner_orig[i]);
            if (i - first_diff) % 16 == 15 {
                println!();
            }
        }
        println!();
        println!(
            "--- REBUILT inner around first divergence [{}..{}] ---",
            first_diff,
            (first_diff + 64).min(rebuilt_gap_end)
        );
        for i in first_diff..(first_diff + 64).min(r_len) {
            if (i - first_diff) % 16 == 0 {
                print!("  {:6}: ", i);
            }
            print!("{:02x} ", inner_rebuilt[i]);
            if (i - first_diff) % 16 == 15 {
                println!();
            }
        }
        println!();

        // Hex dump around where the tail matching starts
        let orig_tail = o_len - end_match;
        let rebuilt_tail = r_len - end_match;
        let ctx = 32;
        println!(
            "\n--- ORIGINAL inner before tail match [{}..{}] ---",
            orig_tail.saturating_sub(ctx),
            orig_tail + ctx.min(end_match)
        );
        for i in orig_tail.saturating_sub(ctx)..orig_tail + ctx.min(end_match) {
            if (i - orig_tail.saturating_sub(ctx)) % 16 == 0 {
                print!("  {:6}: ", i);
            }
            print!("{:02x} ", inner_orig[i]);
            if (i - orig_tail.saturating_sub(ctx)) % 16 == 15 {
                println!();
            }
        }
        println!();
        println!(
            "--- REBUILT inner before tail match [{}..{}] ---",
            rebuilt_tail.saturating_sub(ctx),
            rebuilt_tail + ctx.min(end_match)
        );
        for i in rebuilt_tail.saturating_sub(ctx)..rebuilt_tail + ctx.min(end_match) {
            if (i - rebuilt_tail.saturating_sub(ctx)) % 16 == 0 {
                print!("  {:6}: ", i);
            }
            print!("{:02x} ", inner_rebuilt[i]);
            if (i - rebuilt_tail.saturating_sub(ctx)) % 16 == 15 {
                println!();
            }
        }
        println!();

        // Also: scan the divergent region for where orig and rebuilt match when shifted by 24
        println!("\n--- SHIFT ANALYSIS ---");
        // Check if orig[X..] matches rebuilt[X-24..] for the divergent region
        // i.e., our rebuilt is the same but with 24 bytes removed somewhere
        let shift = (o_len as i64 - r_len as i64) as usize; // = 24
        println!("Total shift: {} bytes", shift);

        // Find all locations where shifting changes — these are where extra bytes exist in orig
        let mut gap_positions: Vec<usize> = Vec::new();
        let mut current_shift: i64 = 0;
        let mut i_o = first_diff;
        let mut i_r = first_diff;
        while i_o < o_len && i_r < r_len {
            if inner_orig[i_o] == inner_rebuilt[i_r] {
                i_o += 1;
                i_r += 1;
            } else {
                // Try advancing orig by 1 to find a resync
                let mut found = false;
                for skip in 1..=24usize {
                    if i_o + skip < o_len && inner_orig[i_o + skip] == inner_rebuilt[i_r] {
                        // Check if this resync holds for at least 8 bytes
                        let mut match_len = 0;
                        for k in 0..8 {
                            if i_o + skip + k < o_len
                                && i_r + k < r_len
                                && inner_orig[i_o + skip + k] == inner_rebuilt[i_r + k]
                            {
                                match_len += 1;
                            } else {
                                break;
                            }
                        }
                        if match_len >= 8 {
                            println!(
                                "  EXTRA {} bytes in original at inner offset {} (0x{:04x})",
                                skip, i_o, i_o
                            );
                            // Print the extra bytes
                            print!("    extra bytes: ");
                            for j in 0..skip {
                                print!("{:02x} ", inner_orig[i_o + j]);
                            }
                            println!();
                            current_shift += skip as i64;
                            gap_positions.push(i_o);
                            i_o += skip;
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    // Content difference, not a gap — advance both
                    i_o += 1;
                    i_r += 1;
                }
            }
        }
        println!("Total extra bytes found in original: {}", current_shift);

        // === DETAILED OBJECT POSITION MAP ===
        // Walk the original inner FB and print absolute positions of all objects
        println!("\n=== ORIGINAL INNER FB OBJECT MAP ===");
        let buf = inner_orig;
        let root_off = read_u32(buf, 0) as usize;
        println!(
            "Root offset: {} (root table at inner pos {})",
            root_off, root_off
        );
        let root_pos = root_off;
        let soff = read_i32(buf, root_pos);
        let vt_pos = (root_pos as i32 - soff) as usize;
        let vt_size = read_u16(buf, vt_pos) as usize;
        let tbl_size = read_u16(buf, vt_pos + 2) as usize;
        println!(
            "Root vtable at {}, size={}, table_size={}",
            vt_pos, vt_size, tbl_size
        );
        println!("Root table spans {}..{}", root_pos, root_pos + tbl_size);

        // Get absolute positions of all referenced objects
        let num_fields = (vt_size - 4) / 2;
        for fi in 0..num_fields {
            let foff = read_u16(buf, vt_pos + 4 + fi * 2) as usize;
            if foff == 0 {
                continue;
            }
            let fpos = root_pos + foff;
            let raw = read_u32(buf, fpos);
            // For offset fields, raw is a relative offset; absolute = fpos + raw
            let abs_target = fpos as u64 + raw as u64;
            println!(
                "  field[{}] at root+{} (inner {}): raw=0x{:08x} → target inner {}",
                fi, foff, fpos, raw, abs_target
            );
        }

        // Walk config_log to get exact positions
        let cfglog_foff = read_u16(buf, vt_pos + 4 + 4 * 2) as usize;
        if cfglog_foff != 0 {
            let fpos = root_pos + cfglog_foff;
            let vec_rel = read_u32(buf, fpos) as usize;
            let vec_pos = fpos + vec_rel;
            let count = read_u32(buf, vec_pos) as usize;
            println!("\nconfig_log vector at inner {} (count={})", vec_pos, count);
            for i in 0..count {
                let off_rel = read_u32(buf, vec_pos + 4 + i * 4) as usize;
                let entry_pos = vec_pos + 4 + i * 4 + off_rel;
                let e_soff = read_i32(buf, entry_pos);
                let e_vt = (entry_pos as i32 - e_soff) as usize;
                let e_vt_size = read_u16(buf, e_vt) as usize;
                let e_tbl_size = read_u16(buf, e_vt + 2) as usize;
                println!(
                    "  config[{}]: table at {}, vtable at {}, vt_size={}, tbl_size={}",
                    i, entry_pos, e_vt, e_vt_size, e_tbl_size
                );
                println!("    table spans {}..{}", entry_pos, entry_pos + e_tbl_size);

                // Get string positions
                let e_nf = (e_vt_size - 4) / 2;
                for fi in 0..e_nf {
                    let ff = read_u16(buf, e_vt + 4 + fi * 2) as usize;
                    if ff == 0 {
                        continue;
                    }
                    let fp = entry_pos + ff;
                    let val = read_u32(buf, fp);
                    // offset fields (3=entry_type, 4=author) → string positions
                    if fi == 3 || fi == 4 {
                        let str_pos = fp + val as usize;
                        let str_len = read_u32(buf, str_pos) as usize;
                        let str_end = str_pos + 4 + str_len + 1; // len prefix + data + null
                        let padded = (str_end + 3) & !3;
                        println!(
                            "    field[{}]: offset at inner {}, string at inner {}..{} (padded to {}), len={}, '{}'",
                            fi,
                            fp,
                            str_pos,
                            str_end,
                            padded,
                            str_len,
                            std::str::from_utf8(&buf[str_pos + 4..str_pos + 4 + str_len])
                                .unwrap_or("?")
                        );
                    } else {
                        println!(
                            "    field[{}]: scalar at inner {}, val=0x{:08x}",
                            fi, fp, val
                        );
                    }
                }
            }
        }

        // Hexdump the region around inner offset 1677884 (the orphaned "admin" string)
        println!("\n=== REGION AROUND ORPHANED 'admin' (inner 1677870..1677910) ===");
        for i in 1677870..1677910.min(o_len) {
            if (i - 1677870) % 16 == 0 {
                print!("  {:7}: ", i);
            }
            print!("{:02x} ", buf[i]);
            if (i - 1677870) % 16 == 15 {
                println!();
            }
        }
        println!();

        // Same region in rebuilt
        // The shift says 16 bytes missing, so rebuilt offset ≈ 1677870
        println!("=== SAME REGION IN REBUILT (inner 1677870..1677910) ===");
        let rbuf = inner_rebuilt;
        for i in 1677870..1677910.min(r_len) {
            if (i - 1677870) % 16 == 0 {
                print!("  {:7}: ", i);
            }
            print!("{:02x} ", rbuf[i]);
            if (i - 1677870) % 16 == 15 {
                println!();
            }
        }
        println!();

        // Hexdump the region around inner offset 1729820..1729870 (the 8 extra bytes area)
        println!("\n=== LOG ENTRY AREA (orig inner 1729790..1729860) ===");
        for i in 1729790..1729860.min(o_len) {
            if (i - 1729790) % 16 == 0 {
                print!("  {:7}: ", i);
            }
            print!("{:02x} ", buf[i]);
            if (i - 1729790) % 16 == 15 {
                println!();
            }
        }
        println!();
        println!("=== LOG ENTRY AREA (rebuilt inner 1729766..1729840) ===");
        for i in 1729766..1729840.min(r_len) {
            if (i - 1729766) % 16 == 0 {
                print!("  {:7}: ", i);
            }
            print!("{:02x} ", rbuf[i]);
            if (i - 1729766) % 16 == 15 {
                println!();
            }
        }
        println!();
    }

    // === Round-trip verification: re-parse rebuilt FlatBuffer ===
    println!("\n=== ROUND-TRIP VERIFICATION ===");
    let reparsed = Module::from_flatbuffer(&rebuilt).expect("reparse rebuilt FlatBuffer");
    assert_eq!(reparsed.version, module.version, "version mismatch");
    assert_eq!(reparsed.author, module.author, "author mismatch");
    assert_eq!(
        reparsed.auth_token, module.auth_token,
        "auth_token mismatch"
    );
    assert_eq!(reparsed.checksum, module.checksum, "checksum mismatch");
    assert_eq!(
        reparsed.buffer_capacity, module.buffer_capacity,
        "buffer_capacity mismatch"
    );
    assert_eq!(reparsed.enabled, module.enabled, "enabled mismatch");
    assert_eq!(
        reparsed.config_log.len(),
        module.config_log.len(),
        "config_log count mismatch"
    );
    assert_eq!(
        reparsed.script_log.len(),
        module.script_log.len(),
        "script_log count mismatch"
    );
    assert_eq!(
        reparsed.languages.len(),
        module.languages.len(),
        "languages count mismatch"
    );
    for (i, (a, b)) in reparsed
        .config_log
        .iter()
        .zip(module.config_log.iter())
        .enumerate()
    {
        assert_eq!(a.entry_id, b.entry_id, "config_log[{}].entry_id", i);
        assert_eq!(a.timestamp, b.timestamp, "config_log[{}].timestamp", i);
        assert_eq!(a.name, b.name, "config_log[{}].name", i);
        assert_eq!(a.author, b.author, "config_log[{}].author", i);
    }
    for (i, (a, b)) in reparsed
        .script_log
        .iter()
        .zip(module.script_log.iter())
        .enumerate()
    {
        assert_eq!(a.entry_id, b.entry_id, "script_log[{}].entry_id", i);
        assert_eq!(a.timestamp, b.timestamp, "script_log[{}].timestamp", i);
        assert_eq!(a.name, b.name, "script_log[{}].name", i);
        assert_eq!(a.author, b.author, "script_log[{}].author", i);
    }
    for (i, (a, b)) in reparsed
        .languages
        .iter()
        .zip(module.languages.iter())
        .enumerate()
    {
        assert_eq!(a.code, b.code, "languages[{}].code", i);
        assert_eq!(
            a.english_name, b.english_name,
            "languages[{}].english_name",
            i
        );
        assert_eq!(a.native_name, b.native_name, "languages[{}].native_name", i);
        assert_eq!(
            a.translations.is_some(),
            b.translations.is_some(),
            "languages[{}].translations",
            i
        );
    }
    println!("All field values verified: OK!");

    // Full pipeline round-trip (encrypt → decrypt → parse)
    let encrypted = pipeline::save_module(&rebuilt).expect("encrypt rebuilt module");
    let decrypted = pipeline::load_module(&encrypted).expect("decrypt rebuilt module");
    let reparsed2 = Module::from_flatbuffer(&decrypted).expect("reparse decrypted rebuilt");
    assert_eq!(reparsed2.version, module.version, "pipeline: version");
    assert_eq!(reparsed2.author, module.author, "pipeline: author");
    assert_eq!(reparsed2.checksum, module.checksum, "pipeline: checksum");
    println!("Pipeline round-trip verified: OK!");

    let out = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/compare_bins/rebuilt_ordered.bin"
    );
    std::fs::write(out, &rebuilt).expect("write");
    println!("\nWrote {}", out);
}

struct LangStrings {
    code: Ref,
    english_name: Ref,
    native_name: Ref,
    translations: Option<Ref>,
}

fn rebuild_correct_order(module: &Module, raw_skin_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut b = FlatccBuilder::new();

    // === PHASE 1: Log entries (created FIRST = highest buffer positions) ===
    // Config entry first, but push 8 bytes of padding before its table
    // (the original binary has 8 zero bytes between config table and config strings)
    let config_offsets: Vec<_> = module
        .config_log
        .iter()
        .map(|e| build_log_entry_with_gap(&mut b, e, 8))
        .collect();
    let script_offsets: Vec<_> = module
        .script_log
        .iter()
        .map(|e| build_log_entry(&mut b, e))
        .collect();

    // === PHASE 2: Language STRING DATA only (no tables yet!) ===
    let mut lang_data: Vec<LangStrings> = Vec::new();
    for lang in &module.languages {
        let translations = match &lang.translations {
            Some(value) => {
                let json_bytes = serialize_translations_json(value)?;
                let json_str = std::str::from_utf8(&json_bytes)
                    .map_err(|e| anyhow::anyhow!("translations JSON not UTF-8: {e}"))?;
                Some(b.create_string(json_str))
            }
            None => None,
        };
        let code = b.create_string(&lang.code);
        let english_name = b.create_string(&lang.english_name);
        let native_name = if lang.native_name == lang.english_name {
            english_name
        } else {
            b.create_string(&lang.native_name)
        };
        lang_data.push(LangStrings {
            code,
            english_name,
            native_name,
            translations,
        });
    }

    // === PHASE 3: extra_data (empty vec) ===
    // Original has 4 bytes of alignment padding between extra_data and language strings
    b.push_zeros(4);
    let extra_data = b.create_vector_u8(&[]);

    // === PHASE 3.5: Orphaned "admin" string ===
    // The original binary has a string "admin" between skin_data and extra_data
    // that is NOT referenced by any field — an artifact of the original build process.
    let _orphaned_admin = b.create_string("admin");

    // === PHASE 4: skin_data (massive 1.6MB blob) ===
    let skin_data = b.create_vector_u8(raw_skin_data);

    // === PHASE 5: auth_token string ===
    let auth_token = b.create_string(&module.auth_token);

    // === PHASE 6: Language TABLES (referencing strings from Phase 2) ===
    // Language tables must be created in the ORIGINAL order: [0, 3, 2, 1, 4].
    // This ensures lang[3] absorbs the 2-byte alignment padding from lang[0]'s
    // 18-byte vtable (which is not 4-aligned), matching the original's tbl_size=18.
    let creation_order: &[usize] = &[0, 3, 2, 1, 4];
    let mut lang_offsets = vec![Ref::dummy(); lang_data.len()];
    for &idx in creation_order {
        let ls = &lang_data[idx];
        b.start_table(7);
        b.table_add_offset(2, ls.code);
        b.table_add_offset(4, ls.english_name);
        b.table_add_offset(5, ls.native_name);
        if let Some(t) = ls.translations {
            b.table_add_offset(6, t);
        }
        lang_offsets[idx] = b.end_table();
    }

    // === PHASE 7: Vector offset arrays ===
    let lang_vec = b.create_vector_offsets(&lang_offsets);
    let script_vec = b.create_vector_offsets(&script_offsets);
    let config_vec = b.create_vector_offsets(&config_offsets);

    // === PHASE 8+9: Root table with INLINE author string ===
    b.start_table(12);
    b.table_add_offset(4, config_vec);
    b.table_add_offset(5, script_vec);
    b.table_add_offset(7, lang_vec);
    b.table_add_offset(1, extra_data);
    let author = b.create_string(&module.author); // INLINE
    b.table_add_offset(2, author);
    b.table_add_offset(9, skin_data);
    b.table_add_u32(3, module.checksum, 0);
    b.table_add_u32(8, module.enabled, 0);
    b.table_add_u32(6, module.buffer_capacity, 0);
    b.table_add_offset(11, auth_token);
    let root = b.end_table();
    let inner_bytes = b.finish_minimal(root);

    // === Outer wrapper ===
    let mut ob = FlatccBuilder::new();
    ob.force_defaults(true);
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, module.version, 0);
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish(wrapper))
}

fn build_log_entry(b: &mut FlatccBuilder, entry: &LogEntry) -> Ref {
    let entry_type = b.create_string(&entry.name);
    let author = b.create_string(&entry.author);
    b.start_table(5);
    // Original C++ builder pushes fields in ascending field ID order
    b.table_add_u32(0, entry.entry_id, 0);
    b.table_add_u32(1, entry.timestamp, 0);
    b.table_add_offset(3, entry_type);
    b.table_add_offset(4, author);
    b.end_table()
}

fn build_log_entry_with_gap(b: &mut FlatccBuilder, entry: &LogEntry, gap: usize) -> Ref {
    let entry_type = b.create_string(&entry.name);
    let author = b.create_string(&entry.author);
    // Insert gap bytes between strings and table (matches original binary layout)
    b.push_zeros(gap);
    b.start_table(5);
    b.table_add_u32(0, entry.entry_id, 0);
    b.table_add_u32(1, entry.timestamp, 0);
    b.table_add_offset(3, entry_type);
    b.table_add_offset(4, author);
    b.end_table()
}
