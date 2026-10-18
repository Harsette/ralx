import { Inflate } from "fflate";

// Preflight central AND local headers before allocating inflated buffers. ZIP64,
// encryption, multi-disk and overlapping entries are deliberately unsupported.
export function vaultZip(bytes: Uint8Array) {
  const fail = (): never => { throw Error("Invalid bounded ZIP"); };
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (p: number) => p >= 0 && p + 2 <= bytes.length ? v.getUint16(p, true) : fail();
  const u32 = (p: number) => p >= 0 && p + 4 <= bytes.length ? v.getUint32(p, true) : fail();
  let end = bytes.length - 22;
  while (end >= Math.max(0, bytes.length - 65557) && u32(end) !== 0x06054b50) end--;
  if (end < 0 || u32(end) !== 0x06054b50 || end + 22 + u16(end + 20) !== bytes.length) fail();
  if (end >= 20 && u32(end - 20) === 0x07064b50) fail();
  const count = u16(end + 10), size = u32(end + 12), start = u32(end + 16);
  if (u16(end + 4) || u16(end + 6) || u16(end + 8) !== count || count > 10000 || count === 65535 || start + size !== end) fail();
  const entries = new Map<string, { crc: number; length: number; method: number; data: number; compressed: number }>();
  let p = start, total = 0, localEnd = 0;
  const extra = (from: number, n: number) => {
    const stop = from + n;
    while (from < stop) {
      if (from + 4 > stop || u16(from) === 1) fail();
      from += 4 + u16(from + 2);
    }
    if (from !== stop) fail();
  };
  for (let i = 0; i < count; i++) {
    if (u32(p) !== 0x02014b50) fail();
    const flags = u16(p + 8), method = u16(p + 10), crc = u32(p + 16), compressed = u32(p + 20), length = u32(p + 24);
    const n = u16(p + 28), x = u16(p + 30), c = u16(p + 32), offset = u32(p + 42);
    if ((flags & ~0x808) || ![0, 8].includes(method) || u16(p + 34) || [compressed, length, offset].includes(0xffffffff)) fail();
    if (p + 46 + n + x + c > end || offset < localEnd || u32(offset) !== 0x04034b50) fail();
    const name = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes.subarray(p + 46, p + 46 + n));
    if (!name || entries.has(name) || name.includes("\0")) fail();
    const ln = u16(offset + 26), lx = u16(offset + 28), data = offset + 30 + ln + lx;
    if (data + compressed > start || u16(offset + 6) !== flags || u16(offset + 8) !== method || ln !== n) fail();
    if (bytes.subarray(offset + 30, offset + 30 + ln).some((b, j) => b !== bytes[p + 46 + j])) fail();
    if (!(flags & 8) && (u32(offset + 14) !== crc || u32(offset + 18) !== compressed || u32(offset + 22) !== length)) fail();
    extra(p + 46 + n, x); extra(offset + 30 + ln, lx);
    total += length;
    if (length > 8 * 1024 * 1024 || total > 16 * 1024 * 1024 || length > Math.max(65536, compressed * 200)) fail();
    localEnd = data + compressed;
    if (method === 0 && compressed !== length) fail();
    entries.set(name, { crc, length, method, data, compressed }); p += 46 + n + x + c;
  }
  if (p !== end) fail();
  // Extract exactly the validated ranges. Never let a second ZIP parser select
  // another directory or allocate from an unchecked decompressed-size field.
  const files: Record<string, Uint8Array> = Object.create(null);
  let actual = 0;
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) { let c = i; for (let b = 0; b < 8; b++) c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0); table[i] = c; }
  for (const [name, entry] of entries) {
    const data = new Uint8Array(entry.length);
    if (entry.method === 0) {
      data.set(bytes.subarray(entry.data, entry.data + entry.compressed));
      actual += data.length;
    } else {
      let written = 0;
      const inflate = new Inflate((chunk) => {
        written += chunk.length; actual += chunk.length;
        if (written > entry.length || actual > 16 * 1024 * 1024) fail();
        data.set(chunk, written - chunk.length);
      });
      // Bound each inflater allocation even when the declared length is false.
      for (let offset = 0; offset < entry.compressed; offset += 1024)
        inflate.push(bytes.subarray(entry.data + offset, entry.data + Math.min(offset + 1024, entry.compressed)), offset + 1024 >= entry.compressed);
      if (!entry.compressed || written !== entry.length) fail();
    }
    let crc = 0xffffffff;
    for (const b of data) crc = (crc >>> 8) ^ table[(crc ^ b) & 255];
    if (((crc ^ 0xffffffff) >>> 0) !== entry.crc) fail();
    files[name] = data;
  }
  return files;
}
