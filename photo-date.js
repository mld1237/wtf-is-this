// Read the date a photo was taken from its embedded camera metadata.
// Works locally and offline; nothing is uploaded to a server.
(function () {
  function captureDate(raw) {
    const match = String(raw || '').trim().match(/^(\d{4})[:\-](\d{2})[:\-](\d{2})(?=\D|$)/);
    if (!match) return '';
    const [, y, m, d] = match;
    const year = Number(y), month = Number(m), day = Number(d);
    const check = new Date(Date.UTC(year, month - 1, day));
    if (year < 1900 || year > new Date().getFullYear() + 1 ||
        check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) return '';
    return y + '-' + m + '-' + d;
  }

  function readDateFromBuffer(buffer) {
    const b = new Uint8Array(buffer), v = new DataView(buffer);
    const within = (pos, len = 1) => Number.isSafeInteger(pos) && pos >= 0 && len >= 0 && pos + len <= b.length;
    const u16 = (p, little = false) => within(p, 2) ? v.getUint16(p, little) : null;
    const u32 = (p, little = false) => within(p, 4) ? v.getUint32(p, little) : null;
    const str = (p, len) => within(p, len) ? String.fromCharCode(...b.subarray(p, p + Math.min(len, 128))) : '';
    const big = (p, len) => {
      if (!within(p, len) || len > 8) return null;
      let n = 0;
      for (let i = 0; i < len; i++) n = n * 256 + b[p + i];
      return Number.isSafeInteger(n) ? n : null;
    };

    function tiff(base) {
      if (!within(base, 8)) return '';
      const signature = str(base, 2);
      if (signature !== 'II' && signature !== 'MM') return '';
      const le = signature === 'II';
      if (u16(base + 2, le) !== 42) return '';
      const pointer = u32(base + 4, le);
      if (pointer === null) return '';

      function fields(relative) {
        const pos = base + relative;
        if (!within(pos, 2)) return {};
        const count = u16(pos, le);
        if (count === null || count > 2048 || !within(pos + 2, count * 12)) return {};
        const result = {};
        for (let i = 0; i < count; i++) {
          const e = pos + 2 + i * 12;
          const tag = u16(e, le), kind = u16(e + 2, le), count = u32(e + 4, le);
          if (tag === 0x8769 && count === 1 && (kind === 4 || kind === 13)) {
            result.exifOffset = u32(e + 8, le);
          } else if ([0x9003, 0x9004, 0x0132].includes(tag) && kind === 2 && count && count < 128) {
            const valuePos = count <= 4 ? e + 8 : base + u32(e + 8, le);
            if (within(valuePos, count)) result[tag] = str(valuePos, count).replace(/\0/g, '');
          }
        }
        return result;
      }
      const main = fields(pointer);
      const exif = main.exifOffset != null ? fields(main.exifOffset) : {};
      return captureDate(exif[0x9003]) || captureDate(main[0x9003]) ||
        captureDate(exif[0x9004]) || captureDate(main[0x9004]) ||
        captureDate(main[0x0132]) || captureDate(exif[0x0132]);
    }

    function jpeg() {
      let p = 2;
      while (within(p, 4)) {
        if (b[p] !== 0xff) { p++; continue; }
        while (b[p] === 0xff) p++;
        const marker = b[p++];
        if (marker === 0xd9 || marker === 0xda) break;
        if (marker === 0x01 || marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7)) continue;
        const length = u16(p);
        if (length == null || length < 2 || !within(p, length)) break;
        if (marker === 0xe1 && str(p + 2, 6) === 'Exif\0\0') {
          const date = tiff(p + 8);
          if (date) return date;
        }
        p += length;
      }
      return '';
    }

    function png() {
      let p = 8;
      while (within(p, 12)) {
        const length = u32(p), type = str(p + 4, 4);
        if (length == null || !within(p + 8, length + 4)) break;
        if (type === 'eXIf') {
          const date = tiff(p + 8);
          if (date) return date;
        }
        if (type === 'tEXt' && length < 4096) {
          const payload = str(p + 8, length);
          const zero = payload.indexOf('\0');
          const key = payload.slice(0, zero).toLowerCase();
          if (zero > 0 && /date|creation time/.test(key)) {
            const date = captureDate(payload.slice(zero + 1));
            if (date) return date;
          }
        }
        if (type === 'IEND') break;
        p += 12 + length;
      }
      return '';
    }

    function boxList(start, end) {
      const boxes = [];
      let p = start;
      while (within(p, 8) && p < end && boxes.length < 10000) {
        let length = u32(p), header = 8;
        if (length === 1) { length = big(p + 8, 8); header = 16; }
        else if (length === 0) length = end - p;
        if (length == null || length < header || p + length > end || !within(p, length)) break;
        boxes.push({type: str(p + 4, 4), start: p, begin: p + header, end: p + length});
        p += length;
      }
      return boxes;
    }

    function heif() {
      const meta = boxList(0, b.length).find(box => box.type === 'meta');
      if (!meta || !within(meta.begin, 4)) return '';
      const children = boxList(meta.begin + 4, meta.end);
      const info = children.find(box => box.type === 'iinf');
      const loc = children.find(box => box.type === 'iloc');
      if (!info || !loc) return '';
      let itemId = null;
      const infoVersion = b[info.begin];
      let p = info.begin + 4;
      const entryCount = infoVersion ? u32(p) : u16(p);
      p += infoVersion ? 4 : 2;
      if (entryCount == null || entryCount > 10000) return '';
      for (const entry of boxList(p, info.end)) {
        if (entry.type !== 'infe') continue;
        const version = b[entry.begin];
        if (version !== 2 && version !== 3) continue;
        const id = version === 2 ? u16(entry.begin + 4) : u32(entry.begin + 4);
        const at = entry.begin + 4 + (version === 2 ? 2 : 4) + 2;
        if (str(at, 4) === 'Exif') { itemId = id; break; }
      }
      if (itemId == null) return '';
      const locVersion = b[loc.begin];
      if (locVersion > 2) return '';
      p = loc.begin + 4;
      const sizes = b[p++], moreSizes = b[p++];
      const offsetSize = sizes >> 4, lengthSize = sizes & 15;
      const baseSize = moreSizes >> 4, indexSize = locVersion ? moreSizes & 15 : 0;
      const number = locVersion === 2 ? u32(p) : u16(p);
      p += locVersion === 2 ? 4 : 2;
      if (number == null || number > 10000) return '';
      const idat = children.find(box => box.type === 'idat');
      for (let n = 0; n < number; n++) {
        const id = locVersion === 2 ? u32(p) : u16(p);
        p += locVersion === 2 ? 4 : 2;
        let method = 0;
        if (locVersion === 1 || locVersion === 2) {method = u16(p) & 15; p += 2;}
        p += 2; // data_reference_index
        const base = big(p, baseSize); p += baseSize;
        const count = u16(p); p += 2;
        if (id == null || base == null || count == null || count > 10000) return '';
        const extents = [];
        for (let e = 0; e < count; e++) {
          if (indexSize) p += indexSize;
          const offset = big(p, offsetSize); p += offsetSize;
          const length = big(p, lengthSize); p += lengthSize;
          if (offset == null || length == null) return '';
          if (id === itemId) {
            const absolute = (method === 1 ? idat?.begin : method === 0 ? 0 : null);
            if (absolute == null || !within(absolute + base + offset, length)) return '';
            extents.push(b.subarray(absolute + base + offset, absolute + base + offset + length));
          }
        }
        if (id !== itemId) continue;
        if (!extents.length) return '';
        const joined = new Uint8Array(extents.reduce((sum, x) => sum + x.length, 0));
        let at = 0;
        for (const extent of extents) { joined.set(extent, at); at += extent.length; }
        // The HEIF Exif item begins with a 4-byte offset to its TIFF header.
        // Some encoders also include an Exif\0\0 prefix; locate a valid TIFF header.
        const inner = new DataView(joined.buffer);
        const itemOffset = joined.length >= 4 ? inner.getUint32(0, false) + 4 : 0;
        const starts = [itemOffset, 4, 0];
        for (let i = 0; i < Math.min(joined.length - 3, 128); i++) {
          if ((joined[i] === 0x49 && joined[i + 1] === 0x49) ||
              (joined[i] === 0x4d && joined[i + 1] === 0x4d)) starts.push(i);
        }
        for (const start of new Set(starts)) {
          if (start < 0 || start >= joined.length) continue;
          // TIFF parser above reads the original file, so parse via a TIFF-only call.
          const date = readDateFromBuffer(joined.buffer.slice(start));
          if (date) return date;
        }
        return '';
      }
      return '';
    }

    if (str(0, 2) === '\xff\xd8') return jpeg();
    if (str(0, 4) === 'II*\0' || str(0, 4) === 'MM\0*') return tiff(0);
    if (str(0, 8) === '\x89PNG\r\n\x1a\n') return png();
    if (str(4, 4) === 'ftyp') return heif();
    return '';
  }

  window.getTakenDateFromPhoto = async function (file) {
    if (!file || typeof file.arrayBuffer !== 'function') return { date: '', source: '' };
    try {
      const date = readDateFromBuffer(await file.arrayBuffer());
      if (date) return { date, source: 'camera' };
    } catch (error) {
      console.warn('Could not read the photo capture date', error);
    }
    // No trustworthy capture date: deliberately leave blank, never assume upload date.
    return { date: '', source: '' };
  };
})();
