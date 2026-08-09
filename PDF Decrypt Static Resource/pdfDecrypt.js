/**
 * Custom PDF Decryption Library for Salesforce LWC
 * Handles password-protected PDFs with RC4 and AES encryption
 * Compatible with Locker Service - no external dependencies
 * 
 * @author Tushar
 */
(function(global) {
    'use strict';

    // ============================================
    // SECTION 1: UTILITY FUNCTIONS
    // ============================================
    
    const Utils = {
        /**
         * Convert string to byte array
         */
        stringToBytes: function(str) {
            const bytes = new Uint8Array(str.length);
            for (let i = 0; i < str.length; i++) {
                bytes[i] = str.charCodeAt(i) & 0xFF;
            }
            return bytes;
        },

        /**
         * Convert byte array to string
         */
        bytesToString: function(bytes) {
            let str = '';
            for (let i = 0; i < bytes.length; i++) {
                str += String.fromCharCode(bytes[i]);
            }
            return str;
        },

        /**
         * Convert hex string to byte array
         */
        hexToBytes: function(hex) {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            }
            return bytes;
        },

        /**
         * Convert byte array to hex string
         */
        bytesToHex: function(bytes) {
            let hex = '';
            for (let i = 0; i < bytes.length; i++) {
                hex += ('0' + bytes[i].toString(16)).slice(-2);
            }
            return hex;
        },

        /**
         * Concatenate multiple Uint8Arrays
         */
        concatBytes: function(...arrays) {
            let totalLength = 0;
            for (const arr of arrays) {
                totalLength += arr.length;
            }
            const result = new Uint8Array(totalLength);
            let offset = 0;
            for (const arr of arrays) {
                result.set(arr, offset);
                offset += arr.length;
            }
            return result;
        },

        /**
         * XOR two byte arrays
         */
        xorBytes: function(a, b) {
            const result = new Uint8Array(a.length);
            for (let i = 0; i < a.length; i++) {
                result[i] = a[i] ^ b[i % b.length];
            }
            return result;
        },

        /**
         * Pad PKCS7
         */
        padPKCS7: function(data, blockSize) {
            const padding = blockSize - (data.length % blockSize);
            const result = new Uint8Array(data.length + padding);
            result.set(data);
            for (let i = data.length; i < result.length; i++) {
                result[i] = padding;
            }
            return result;
        },

        /**
         * Unpad PKCS7
         */
        unpadPKCS7: function(data) {
            const padding = data[data.length - 1];
            if (padding > 16 || padding === 0) {
                return data; // Invalid padding, return as-is
            }
            // Verify padding
            for (let i = data.length - padding; i < data.length; i++) {
                if (data[i] !== padding) {
                    return data; // Invalid padding
                }
            }
            return data.slice(0, data.length - padding);
        },

        /**
         * Build a searchable Latin-1 string from PDF bytes.
         * For large PDFs, encryption/trailer markers live near the end, so we
         * always include both the head and the tail (not just the first 50KB).
         */
        getSearchablePdfText: function(pdfData, headBytes, tailBytes) {
            if (!(pdfData instanceof Uint8Array)) {
                pdfData = new Uint8Array(pdfData);
            }
            headBytes = headBytes || 65536;
            tailBytes = tailBytes || 131072;

            // Modest files: search the entire document
            if (pdfData.length <= headBytes + tailBytes) {
                return this.bytesToString(pdfData);
            }

            const head = this.bytesToString(pdfData.subarray(0, headBytes));
            const tail = this.bytesToString(pdfData.subarray(pdfData.length - tailBytes));
            return head + '\n' + tail;
        },

        /**
         * True if raw PDF bytes contain standard encryption markers.
         */
        hasEncryptionMarkers: function(pdfData) {
            const pdfStr = this.getSearchablePdfText(pdfData);
            return pdfStr.includes('/Filter/Standard') ||
                   pdfStr.includes('/Filter /Standard') ||
                   /\/Encrypt\s+\d+\s+\d+\s+R/.test(pdfStr);
        }
    };

    // ============================================
    // SECTION 1b: STREAM PREDICTOR (PNG / TIFF)
    // Required for many large PDF XRef streams
    // ============================================

    const StreamPredictor = {
        paeth: function(a, b, c) {
            const p = a + b - c;
            const pa = Math.abs(p - a);
            const pb = Math.abs(p - b);
            const pc = Math.abs(p - c);
            if (pa <= pb && pa <= pc) return a;
            if (pb <= pc) return b;
            return c;
        },

        /**
         * Undo PNG/TIFF predictors after FlateDecode.
         * PDF DecodeParms: /Predictor, /Columns, /Colors, /BitsPerComponent
         */
        apply: function(data, params) {
            if (!params || !(data instanceof Uint8Array) || data.length === 0) {
                return data;
            }

            const predictor = params['/Predictor'] || params.Predictor || 1;
            if (predictor <= 1) {
                return data;
            }

            const columns = params['/Columns'] || params.Columns || 1;
            const colors = params['/Colors'] || params.Colors || 1;
            const bpc = params['/BitsPerComponent'] || params.BitsPerComponent || 8;
            const rowLength = Math.ceil((columns * colors * bpc) / 8);
            if (rowLength <= 0) {
                return data;
            }

            // TIFF predictor
            if (predictor === 2) {
                const rowCount = Math.floor(data.length / rowLength);
                const output = new Uint8Array(rowCount * rowLength);
                const bpp = Math.max(1, Math.ceil((colors * bpc) / 8));

                for (let i = 0; i < rowCount; i++) {
                    const rowStart = i * rowLength;
                    for (let j = 0; j < rowLength; j++) {
                        const raw = data[rowStart + j];
                        const left = j >= bpp ? output[rowStart + j - bpp] : 0;
                        output[rowStart + j] = (raw + left) & 0xFF;
                    }
                }
                return output;
            }

            // PNG predictors (10-15): each row starts with a filter-type byte
            if (predictor >= 10 && predictor <= 15) {
                const bytesPerRow = rowLength + 1;
                const rowCount = Math.floor(data.length / bytesPerRow);
                if (rowCount === 0) {
                    return data;
                }

                const output = new Uint8Array(rowCount * rowLength);
                const bpp = Math.max(1, Math.ceil((colors * bpc) / 8));
                let prev = new Uint8Array(rowLength);

                for (let i = 0; i < rowCount; i++) {
                    const rowStart = i * bytesPerRow;
                    const filterType = data[rowStart];
                    const outOffset = i * rowLength;

                    for (let j = 0; j < rowLength; j++) {
                        const raw = data[rowStart + 1 + j];
                        const left = j >= bpp ? output[outOffset + j - bpp] : 0;
                        const up = prev[j];
                        const upLeft = j >= bpp ? prev[j - bpp] : 0;
                        let val = raw;

                        switch (filterType) {
                            case 1: // Sub
                                val = (raw + left) & 0xFF;
                                break;
                            case 2: // Up
                                val = (raw + up) & 0xFF;
                                break;
                            case 3: // Average
                                val = (raw + ((left + up) >> 1)) & 0xFF;
                                break;
                            case 4: // Paeth
                                val = (raw + this.paeth(left, up, upLeft)) & 0xFF;
                                break;
                            default: // None (0) or unknown
                                val = raw;
                                break;
                        }

                        output[outOffset + j] = val;
                    }

                    prev = output.subarray(outOffset, outOffset + rowLength);
                }

                console.log('PDFDecrypt: Applied PNG predictor', predictor,
                    'columns=', columns, 'rows=', rowCount,
                    'in=', data.length, 'out=', output.length);
                return output;
            }

            return data;
        }
    };

    // ============================================
    // SECTION 2: MD5 IMPLEMENTATION
    // ============================================
    
    const MD5 = (function() {
        function md5cycle(x, k) {
            let a = x[0], b = x[1], c = x[2], d = x[3];

            a = ff(a, b, c, d, k[0], 7, -680876936);
            d = ff(d, a, b, c, k[1], 12, -389564586);
            c = ff(c, d, a, b, k[2], 17, 606105819);
            b = ff(b, c, d, a, k[3], 22, -1044525330);
            a = ff(a, b, c, d, k[4], 7, -176418897);
            d = ff(d, a, b, c, k[5], 12, 1200080426);
            c = ff(c, d, a, b, k[6], 17, -1473231341);
            b = ff(b, c, d, a, k[7], 22, -45705983);
            a = ff(a, b, c, d, k[8], 7, 1770035416);
            d = ff(d, a, b, c, k[9], 12, -1958414417);
            c = ff(c, d, a, b, k[10], 17, -42063);
            b = ff(b, c, d, a, k[11], 22, -1990404162);
            a = ff(a, b, c, d, k[12], 7, 1804603682);
            d = ff(d, a, b, c, k[13], 12, -40341101);
            c = ff(c, d, a, b, k[14], 17, -1502002290);
            b = ff(b, c, d, a, k[15], 22, 1236535329);

            a = gg(a, b, c, d, k[1], 5, -165796510);
            d = gg(d, a, b, c, k[6], 9, -1069501632);
            c = gg(c, d, a, b, k[11], 14, 643717713);
            b = gg(b, c, d, a, k[0], 20, -373897302);
            a = gg(a, b, c, d, k[5], 5, -701558691);
            d = gg(d, a, b, c, k[10], 9, 38016083);
            c = gg(c, d, a, b, k[15], 14, -660478335);
            b = gg(b, c, d, a, k[4], 20, -405537848);
            a = gg(a, b, c, d, k[9], 5, 568446438);
            d = gg(d, a, b, c, k[14], 9, -1019803690);
            c = gg(c, d, a, b, k[3], 14, -187363961);
            b = gg(b, c, d, a, k[8], 20, 1163531501);
            a = gg(a, b, c, d, k[13], 5, -1444681467);
            d = gg(d, a, b, c, k[2], 9, -51403784);
            c = gg(c, d, a, b, k[7], 14, 1735328473);
            b = gg(b, c, d, a, k[12], 20, -1926607734);

            a = hh(a, b, c, d, k[5], 4, -378558);
            d = hh(d, a, b, c, k[8], 11, -2022574463);
            c = hh(c, d, a, b, k[11], 16, 1839030562);
            b = hh(b, c, d, a, k[14], 23, -35309556);
            a = hh(a, b, c, d, k[1], 4, -1530992060);
            d = hh(d, a, b, c, k[4], 11, 1272893353);
            c = hh(c, d, a, b, k[7], 16, -155497632);
            b = hh(b, c, d, a, k[10], 23, -1094730640);
            a = hh(a, b, c, d, k[13], 4, 681279174);
            d = hh(d, a, b, c, k[0], 11, -358537222);
            c = hh(c, d, a, b, k[3], 16, -722521979);
            b = hh(b, c, d, a, k[6], 23, 76029189);
            a = hh(a, b, c, d, k[9], 4, -640364487);
            d = hh(d, a, b, c, k[12], 11, -421815835);
            c = hh(c, d, a, b, k[15], 16, 530742520);
            b = hh(b, c, d, a, k[2], 23, -995338651);

            a = ii(a, b, c, d, k[0], 6, -198630844);
            d = ii(d, a, b, c, k[7], 10, 1126891415);
            c = ii(c, d, a, b, k[14], 15, -1416354905);
            b = ii(b, c, d, a, k[5], 21, -57434055);
            a = ii(a, b, c, d, k[12], 6, 1700485571);
            d = ii(d, a, b, c, k[3], 10, -1894986606);
            c = ii(c, d, a, b, k[10], 15, -1051523);
            b = ii(b, c, d, a, k[1], 21, -2054922799);
            a = ii(a, b, c, d, k[8], 6, 1873313359);
            d = ii(d, a, b, c, k[15], 10, -30611744);
            c = ii(c, d, a, b, k[6], 15, -1560198380);
            b = ii(b, c, d, a, k[13], 21, 1309151649);
            a = ii(a, b, c, d, k[4], 6, -145523070);
            d = ii(d, a, b, c, k[11], 10, -1120210379);
            c = ii(c, d, a, b, k[2], 15, 718787259);
            b = ii(b, c, d, a, k[9], 21, -343485551);

            x[0] = add32(a, x[0]);
            x[1] = add32(b, x[1]);
            x[2] = add32(c, x[2]);
            x[3] = add32(d, x[3]);
        }

        function cmn(q, a, b, x, s, t) {
            a = add32(add32(a, q), add32(x, t));
            return add32((a << s) | (a >>> (32 - s)), b);
        }

        function ff(a, b, c, d, x, s, t) {
            return cmn((b & c) | ((~b) & d), a, b, x, s, t);
        }

        function gg(a, b, c, d, x, s, t) {
            return cmn((b & d) | (c & (~d)), a, b, x, s, t);
        }

        function hh(a, b, c, d, x, s, t) {
            return cmn(b ^ c ^ d, a, b, x, s, t);
        }

        function ii(a, b, c, d, x, s, t) {
            return cmn(c ^ (b | (~d)), a, b, x, s, t);
        }

        function add32(a, b) {
            return (a + b) & 0xFFFFFFFF;
        }

        function md5blk(s) {
            const md5blks = [];
            for (let i = 0; i < 64; i += 4) {
                md5blks[i >> 2] = s[i] + (s[i + 1] << 8) + (s[i + 2] << 16) + (s[i + 3] << 24);
            }
            return md5blks;
        }

        return {
            hash: function(bytes) {
                if (!(bytes instanceof Uint8Array)) {
                    bytes = Utils.stringToBytes(bytes);
                }
                
                const n = bytes.length;
                let state = [1732584193, -271733879, -1732584194, 271733878];
                let i;
                
                for (i = 64; i <= n; i += 64) {
                    md5cycle(state, md5blk(bytes.slice(i - 64, i)));
                }
                
                const tail = new Uint8Array(64);
                const remaining = n - (i - 64);
                tail.set(bytes.slice(i - 64, n));
                tail[remaining] = 0x80;
                
                if (remaining > 55) {
                    md5cycle(state, md5blk(tail));
                    tail.fill(0);
                }
                
                tail[56] = (n * 8) & 0xFF;
                tail[57] = ((n * 8) >> 8) & 0xFF;
                tail[58] = ((n * 8) >> 16) & 0xFF;
                tail[59] = ((n * 8) >> 24) & 0xFF;
                md5cycle(state, md5blk(tail));
                
                const result = new Uint8Array(16);
                for (let j = 0; j < 4; j++) {
                    result[j * 4] = state[j] & 0xFF;
                    result[j * 4 + 1] = (state[j] >> 8) & 0xFF;
                    result[j * 4 + 2] = (state[j] >> 16) & 0xFF;
                    result[j * 4 + 3] = (state[j] >> 24) & 0xFF;
                }
                return result;
            }
        };
    })();

    // ============================================
    // SECTION 3: SHA-256 IMPLEMENTATION
    // ============================================
    
    const SHA256 = (function() {
        const K = new Uint32Array([
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]);

        function rotr(x, n) {
            return (x >>> n) | (x << (32 - n));
        }

        function ch(x, y, z) {
            return (x & y) ^ (~x & z);
        }

        function maj(x, y, z) {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        function sigma0(x) {
            return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
        }

        function sigma1(x) {
            return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
        }

        function gamma0(x) {
            return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
        }

        function gamma1(x) {
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
        }

        return {
            hash: function(bytes) {
                if (!(bytes instanceof Uint8Array)) {
                    bytes = Utils.stringToBytes(bytes);
                }

                let H = new Uint32Array([
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                ]);

                const l = bytes.length;
                const k = (512 + 448 - ((l * 8 + 1) % 512)) % 512;
                const paddedLen = l + 1 + (k + 64) / 8;
                const padded = new Uint8Array(paddedLen);
                padded.set(bytes);
                padded[l] = 0x80;

                const bitLen = l * 8;
                for (let i = 0; i < 8; i++) {
                    padded[paddedLen - 8 + i] = (bitLen / Math.pow(2, 56 - i * 8)) & 0xFF;
                }

                const W = new Uint32Array(64);

                for (let offset = 0; offset < paddedLen; offset += 64) {
                    for (let i = 0; i < 16; i++) {
                        W[i] = (padded[offset + i * 4] << 24) |
                               (padded[offset + i * 4 + 1] << 16) |
                               (padded[offset + i * 4 + 2] << 8) |
                               padded[offset + i * 4 + 3];
                    }

                    for (let i = 16; i < 64; i++) {
                        W[i] = (gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16]) >>> 0;
                    }

                    let [a, b, c, d, e, f, g, h] = H;

                    for (let i = 0; i < 64; i++) {
                        const T1 = (h + sigma1(e) + ch(e, f, g) + K[i] + W[i]) >>> 0;
                        const T2 = (sigma0(a) + maj(a, b, c)) >>> 0;
                        h = g;
                        g = f;
                        f = e;
                        e = (d + T1) >>> 0;
                        d = c;
                        c = b;
                        b = a;
                        a = (T1 + T2) >>> 0;
                    }

                    H[0] = (H[0] + a) >>> 0;
                    H[1] = (H[1] + b) >>> 0;
                    H[2] = (H[2] + c) >>> 0;
                    H[3] = (H[3] + d) >>> 0;
                    H[4] = (H[4] + e) >>> 0;
                    H[5] = (H[5] + f) >>> 0;
                    H[6] = (H[6] + g) >>> 0;
                    H[7] = (H[7] + h) >>> 0;
                }

                const result = new Uint8Array(32);
                for (let i = 0; i < 8; i++) {
                    result[i * 4] = (H[i] >> 24) & 0xFF;
                    result[i * 4 + 1] = (H[i] >> 16) & 0xFF;
                    result[i * 4 + 2] = (H[i] >> 8) & 0xFF;
                    result[i * 4 + 3] = H[i] & 0xFF;
                }
                return result;
            }
        };
    })();

    // ============================================
    // SECTION 4: RC4 IMPLEMENTATION
    // ============================================
    
    const RC4 = {
        /**
         * RC4 encrypt/decrypt (same operation)
         */
        crypt: function(key, data) {
            // Initialize S-box
            const S = new Uint8Array(256);
            for (let i = 0; i < 256; i++) {
                S[i] = i;
            }

            // Key scheduling
            let j = 0;
            for (let i = 0; i < 256; i++) {
                j = (j + S[i] + key[i % key.length]) & 0xFF;
                [S[i], S[j]] = [S[j], S[i]];
            }

            // Generate keystream and XOR with data
            const result = new Uint8Array(data.length);
            let i = 0;
            j = 0;
            for (let k = 0; k < data.length; k++) {
                i = (i + 1) & 0xFF;
                j = (j + S[i]) & 0xFF;
                [S[i], S[j]] = [S[j], S[i]];
                result[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF];
            }
            return result;
        }
    };

    // ============================================
    // SECTION 5: AES IMPLEMENTATION
    // ============================================
    
    const AES = (function() {
        // S-box
        const SBOX = new Uint8Array([
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]);

        // Inverse S-box
        const INV_SBOX = new Uint8Array([
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]);

        // Round constants
        const RCON = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

        function gmul(a, b) {
            let p = 0;
            for (let i = 0; i < 8; i++) {
                if (b & 1) p ^= a;
                const hi = a & 0x80;
                a = (a << 1) & 0xFF;
                if (hi) a ^= 0x1b;
                b >>= 1;
            }
            return p;
        }

        function subBytes(state) {
            for (let i = 0; i < 16; i++) {
                state[i] = SBOX[state[i]];
            }
        }

        function invSubBytes(state) {
            for (let i = 0; i < 16; i++) {
                state[i] = INV_SBOX[state[i]];
            }
        }

        function shiftRows(state) {
            let temp = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = temp;

            temp = state[2];
            state[2] = state[10];
            state[10] = temp;
            temp = state[6];
            state[6] = state[14];
            state[14] = temp;

            temp = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = state[3];
            state[3] = temp;
        }

        function invShiftRows(state) {
            let temp = state[13];
            state[13] = state[9];
            state[9] = state[5];
            state[5] = state[1];
            state[1] = temp;

            temp = state[2];
            state[2] = state[10];
            state[10] = temp;
            temp = state[6];
            state[6] = state[14];
            state[14] = temp;

            temp = state[3];
            state[3] = state[7];
            state[7] = state[11];
            state[11] = state[15];
            state[15] = temp;
        }

        function mixColumns(state) {
            for (let i = 0; i < 4; i++) {
                const a = state[i * 4];
                const b = state[i * 4 + 1];
                const c = state[i * 4 + 2];
                const d = state[i * 4 + 3];
                state[i * 4] = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d;
                state[i * 4 + 1] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d;
                state[i * 4 + 2] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3);
                state[i * 4 + 3] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2);
            }
        }

        function invMixColumns(state) {
            for (let i = 0; i < 4; i++) {
                const a = state[i * 4];
                const b = state[i * 4 + 1];
                const c = state[i * 4 + 2];
                const d = state[i * 4 + 3];
                state[i * 4] = gmul(a, 14) ^ gmul(b, 11) ^ gmul(c, 13) ^ gmul(d, 9);
                state[i * 4 + 1] = gmul(a, 9) ^ gmul(b, 14) ^ gmul(c, 11) ^ gmul(d, 13);
                state[i * 4 + 2] = gmul(a, 13) ^ gmul(b, 9) ^ gmul(c, 14) ^ gmul(d, 11);
                state[i * 4 + 3] = gmul(a, 11) ^ gmul(b, 13) ^ gmul(c, 9) ^ gmul(d, 14);
            }
        }

        function addRoundKey(state, roundKey) {
            for (let i = 0; i < 16; i++) {
                state[i] ^= roundKey[i];
            }
        }

        function keyExpansion(key) {
            const keyLen = key.length;
            const rounds = keyLen === 16 ? 10 : (keyLen === 24 ? 12 : 14);
            const nk = keyLen / 4;
            const expandedKey = new Uint8Array((rounds + 1) * 16);
            
            expandedKey.set(key);
            
            for (let i = nk; i < (rounds + 1) * 4; i++) {
                let temp = expandedKey.slice((i - 1) * 4, i * 4);
                
                if (i % nk === 0) {
                    // RotWord
                    const t = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = t;
                    // SubWord
                    for (let j = 0; j < 4; j++) {
                        temp[j] = SBOX[temp[j]];
                    }
                    temp[0] ^= RCON[(i / nk) - 1];
                } else if (nk > 6 && i % nk === 4) {
                    for (let j = 0; j < 4; j++) {
                        temp[j] = SBOX[temp[j]];
                    }
                }
                
                for (let j = 0; j < 4; j++) {
                    expandedKey[i * 4 + j] = expandedKey[(i - nk) * 4 + j] ^ temp[j];
                }
            }
            
            return { expandedKey, rounds };
        }

        return {
            /**
             * AES decrypt (CBC mode)
             */
            decryptCBC: function(key, iv, data) {
                const { expandedKey, rounds } = keyExpansion(key);
                const result = new Uint8Array(data.length);
                let prevBlock = iv;

                for (let offset = 0; offset < data.length; offset += 16) {
                    const block = data.slice(offset, offset + 16);
                    const state = new Uint8Array(block);

                    // Initial round key
                    addRoundKey(state, expandedKey.slice(rounds * 16, (rounds + 1) * 16));

                    // Main rounds
                    for (let round = rounds - 1; round > 0; round--) {
                        invShiftRows(state);
                        invSubBytes(state);
                        addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
                        invMixColumns(state);
                    }

                    // Final round
                    invShiftRows(state);
                    invSubBytes(state);
                    addRoundKey(state, expandedKey.slice(0, 16));

                    // XOR with previous ciphertext block (CBC)
                    for (let i = 0; i < 16; i++) {
                        result[offset + i] = state[i] ^ prevBlock[i];
                    }
                    prevBlock = block;
                }

                return Utils.unpadPKCS7(result);
            },

            /**
             * AES-CBC decrypt without PKCS7 unpadding (UE/OE use no padding).
             */
            decryptCBCNoPad: function(key, iv, data) {
                const { expandedKey, rounds } = keyExpansion(key);
                const result = new Uint8Array(data.length);
                let prevBlock = iv;

                for (let offset = 0; offset < data.length; offset += 16) {
                    const block = data.slice(offset, offset + 16);
                    const state = new Uint8Array(block);

                    addRoundKey(state, expandedKey.slice(rounds * 16, (rounds + 1) * 16));

                    for (let round = rounds - 1; round > 0; round--) {
                        invShiftRows(state);
                        invSubBytes(state);
                        addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
                        invMixColumns(state);
                    }

                    invShiftRows(state);
                    invSubBytes(state);
                    addRoundKey(state, expandedKey.slice(0, 16));

                    for (let i = 0; i < 16; i++) {
                        result[offset + i] = state[i] ^ prevBlock[i];
                    }
                    prevBlock = block;
                }

                return result;
            },

            /**
             * AES encrypt (CBC mode)
             */
            encryptCBC: function(key, iv, data) {
                const { expandedKey, rounds } = keyExpansion(key);
                const padded = Utils.padPKCS7(data, 16);
                const result = new Uint8Array(padded.length);
                let prevBlock = iv;

                for (let offset = 0; offset < padded.length; offset += 16) {
                    const state = new Uint8Array(16);
                    
                    // XOR with previous ciphertext block (CBC)
                    for (let i = 0; i < 16; i++) {
                        state[i] = padded[offset + i] ^ prevBlock[i];
                    }

                    // Initial round key
                    addRoundKey(state, expandedKey.slice(0, 16));

                    // Main rounds
                    for (let round = 1; round < rounds; round++) {
                        subBytes(state);
                        shiftRows(state);
                        mixColumns(state);
                        addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
                    }

                    // Final round
                    subBytes(state);
                    shiftRows(state);
                    addRoundKey(state, expandedKey.slice(rounds * 16, (rounds + 1) * 16));

                    result.set(state, offset);
                    prevBlock = state;
                }

                return result;
            }
        };
    })();

    // ============================================
    // SECTION 6: ZLIB/DEFLATE DECOMPRESSION
    // ============================================
    
    const Inflate = (function() {
        // Fixed Huffman code lengths
        const FIXED_LITERAL_LENGTHS = new Uint8Array(288);
        for (let i = 0; i <= 143; i++) FIXED_LITERAL_LENGTHS[i] = 8;
        for (let i = 144; i <= 255; i++) FIXED_LITERAL_LENGTHS[i] = 9;
        for (let i = 256; i <= 279; i++) FIXED_LITERAL_LENGTHS[i] = 7;
        for (let i = 280; i <= 287; i++) FIXED_LITERAL_LENGTHS[i] = 8;

        const FIXED_DISTANCE_LENGTHS = new Uint8Array(32).fill(5);

        const LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
        const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
        const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
        const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
        const CODE_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

        class BitReader {
            constructor(data) {
                this.data = data;
                this.pos = 0;
                this.bitPos = 0;
                this.buffer = 0;
                this.bufferBits = 0;
                this.eof = false;
            }

            readBits(n) {
                while (this.bufferBits < n) {
                    if (this.pos >= this.data.length) {
                        this.eof = true;
                        // Return what we have, padded with zeros
                        if (this.bufferBits > 0) {
                            const result = this.buffer & ((1 << Math.min(n, this.bufferBits)) - 1);
                            this.buffer = 0;
                            this.bufferBits = 0;
                            return result;
                        }
                        throw new Error('Unexpected end of data');
                    }
                    this.buffer |= this.data[this.pos++] << this.bufferBits;
                    this.bufferBits += 8;
                }
                const result = this.buffer & ((1 << n) - 1);
                this.buffer >>= n;
                this.bufferBits -= n;
                return result;
            }

            readByte() {
                this.buffer = 0;
                this.bufferBits = 0;
                if (this.pos >= this.data.length) {
                    this.eof = true;
                    return 0;
                }
                return this.data[this.pos++];
            }

            alignToByte() {
                this.buffer = 0;
                this.bufferBits = 0;
            }
            
            hasMoreData() {
                return this.pos < this.data.length || this.bufferBits > 0;
            }
        }

        function buildHuffmanTable(lengths) {
            const maxLen = Math.max(...lengths);
            const counts = new Uint16Array(maxLen + 1);
            const nextCode = new Uint16Array(maxLen + 1);
            const table = new Int16Array(1 << maxLen);
            table.fill(-1);

            for (let i = 0; i < lengths.length; i++) {
                if (lengths[i] > 0) counts[lengths[i]]++;
            }

            let code = 0;
            for (let len = 1; len <= maxLen; len++) {
                code = (code + counts[len - 1]) << 1;
                nextCode[len] = code;
            }

            for (let sym = 0; sym < lengths.length; sym++) {
                const len = lengths[sym];
                if (len > 0) {
                    let c = nextCode[len]++;
                    // Reverse bits
                    let reversed = 0;
                    for (let i = 0; i < len; i++) {
                        reversed = (reversed << 1) | (c & 1);
                        c >>= 1;
                    }
                    // Fill table
                    for (let i = reversed; i < (1 << maxLen); i += (1 << len)) {
                        table[i] = (sym << 8) | len;
                    }
                }
            }

            return { table, maxLen };
        }

        function decodeSymbol(reader, huffman) {
            let bits = 0;
            let len = 0;
            
            while (len < huffman.maxLen) {
                try {
                    bits |= reader.readBits(1) << len;
                } catch (e) {
                    // EOF reached - return end of block symbol if we have partial match
                    if (reader.eof) {
                        return 256; // End of block
                    }
                    throw e;
                }
                len++;
                const entry = huffman.table[bits];
                if (entry !== -1 && (entry & 0xFF) === len) {
                    return entry >> 8;
                }
            }
            // If we can't decode, assume end of block
            if (reader.eof) {
                return 256;
            }
            throw new Error('Invalid Huffman code');
        }

        return {
            inflate: function(data) {
                // Check for zlib header
                let startOffset = 0;
                if (data.length >= 2) {
                    const cmf = data[0];
                    const flg = data[1];
                    if ((cmf & 0x0F) === 8 && ((cmf * 256 + flg) % 31) === 0) {
                        startOffset = 2;
                        if (flg & 0x20) {
                            startOffset += 4; // Skip FDICT
                        }
                    }
                }

                const reader = new BitReader(data.slice(startOffset));
                const output = [];
                let bfinal = 0;

                try {
                    while (!bfinal && !reader.eof) {
                        bfinal = reader.readBits(1);
                        const btype = reader.readBits(2);

                        if (btype === 0) {
                            // Stored block
                            reader.alignToByte();
                            const len = reader.readByte() | (reader.readByte() << 8);
                            reader.readByte(); reader.readByte(); // nlen
                            for (let i = 0; i < len && !reader.eof; i++) {
                                output.push(reader.readByte());
                            }
                        } else if (btype === 1 || btype === 2) {
                            // Compressed block
                            let litHuffman, distHuffman;

                            if (btype === 1) {
                                // Fixed Huffman
                                litHuffman = buildHuffmanTable(FIXED_LITERAL_LENGTHS);
                                distHuffman = buildHuffmanTable(FIXED_DISTANCE_LENGTHS);
                            } else {
                                // Dynamic Huffman
                                const hlit = reader.readBits(5) + 257;
                                const hdist = reader.readBits(5) + 1;
                                const hclen = reader.readBits(4) + 4;

                                const codeLengths = new Uint8Array(19);
                                for (let i = 0; i < hclen; i++) {
                                    codeLengths[CODE_ORDER[i]] = reader.readBits(3);
                                }

                                const codeHuffman = buildHuffmanTable(codeLengths);
                                const lengths = new Uint8Array(hlit + hdist);
                                let i = 0;

                                while (i < hlit + hdist && !reader.eof) {
                                    const sym = decodeSymbol(reader, codeHuffman);
                                    if (sym < 16) {
                                        lengths[i++] = sym;
                                    } else if (sym === 16) {
                                        const repeat = reader.readBits(2) + 3;
                                        for (let j = 0; j < repeat && i < hlit + hdist; j++) {
                                            lengths[i] = lengths[i - 1];
                                            i++;
                                        }
                                    } else if (sym === 17) {
                                        i += reader.readBits(3) + 3;
                                    } else {
                                        i += reader.readBits(7) + 11;
                                    }
                                }

                                litHuffman = buildHuffmanTable(lengths.slice(0, hlit));
                                distHuffman = buildHuffmanTable(lengths.slice(hlit));
                            }

                            // Decode symbols
                            while (!reader.eof) {
                                const sym = decodeSymbol(reader, litHuffman);
                                if (sym < 256) {
                                    output.push(sym);
                                } else if (sym === 256) {
                                    break;
                                } else {
                                    const lenIdx = sym - 257;
                                    if (lenIdx < 0 || lenIdx >= LENGTH_BASE.length) {
                                        break; // Invalid length code
                                    }
                                    let length = LENGTH_BASE[lenIdx];
                                    if (LENGTH_EXTRA[lenIdx] > 0) {
                                        length += reader.readBits(LENGTH_EXTRA[lenIdx]);
                                    }

                                    const distSym = decodeSymbol(reader, distHuffman);
                                    if (distSym < 0 || distSym >= DIST_BASE.length) {
                                        break; // Invalid distance code
                                    }
                                    let distance = DIST_BASE[distSym];
                                    if (DIST_EXTRA[distSym] > 0) {
                                        distance += reader.readBits(DIST_EXTRA[distSym]);
                                    }

                                    const start = output.length - distance;
                                    for (let j = 0; j < length; j++) {
                                        output.push(output[start + j]);
                                    }
                                }
                            }
                        } else if (btype === 3) {
                            throw new Error('Invalid block type 3');
                        }
                    }
                } catch (e) {
                    // If we have some output, return it instead of failing completely
                    if (output.length > 0) {
                        console.warn('PDFDecrypt: Inflate ended early with error:', e.message, 'Returning', output.length, 'bytes');
                        return new Uint8Array(output);
                    }
                    throw e;
                }

                return new Uint8Array(output);
            }
        };
    })();

    // ============================================
    // SECTION 7: PDF PARSER
    // ============================================
    
    class PDFParser {
        constructor(data) {
            this.data = data instanceof Uint8Array ? data : new Uint8Array(data);
            this.pos = 0;
            this.objects = new Map();
            this.xref = new Map();
            this.objectStreams = new Map(); // Track objects stored in object streams (type 2)
            this.trailer = null;
            this.encryptDict = null;
            this.idArray = null;
        }

        parse() {
            console.log('PDFDecrypt: Starting PDF parse...');
            this.parseXRef();
            this.parseTrailer();
            console.log('PDFDecrypt: Found', this.xref.size, 'objects');
            return this;
        }

        findString(str, startPos = 0) {
            const bytes = Utils.stringToBytes(str);
            outer: for (let i = startPos; i < this.data.length - bytes.length; i++) {
                for (let j = 0; j < bytes.length; j++) {
                    if (this.data[i + j] !== bytes[j]) continue outer;
                }
                return i;
            }
            return -1;
        }

        findStringReverse(str, startPos = this.data.length) {
            const bytes = Utils.stringToBytes(str);
            outer: for (let i = startPos - bytes.length; i >= 0; i--) {
                for (let j = 0; j < bytes.length; j++) {
                    if (this.data[i + j] !== bytes[j]) continue outer;
                }
                return i;
            }
            return -1;
        }

        parseXRef() {
            // Find startxref
            const startxrefPos = this.findStringReverse('startxref');
            if (startxrefPos === -1) {
                console.warn('PDFDecrypt: Cannot find startxref, falling back to object scan');
                this.scanForObjects();
                return;
            }

            this.pos = startxrefPos + 9;
            this.skipWhitespace();
            let xrefOffset = this.parseNumber();

            // Process all xref sections (following /Prev chain for incremental updates)
            const processedOffsets = new Set();
            let parseSuccess = false;
            
            while (xrefOffset && !processedOffsets.has(xrefOffset)) {
                processedOffsets.add(xrefOffset);
                
                this.pos = xrefOffset;
                this.skipWhitespace();

                // Check if it's xref table or xref stream
                const next5 = Utils.bytesToString(this.data.slice(this.pos, this.pos + 5));
                let prevOffset = null;
                
                try {
                    if (next5.startsWith('xref')) {
                        prevOffset = this.parseXRefTable();
                        parseSuccess = true;
                    } else {
                        // XRef stream
                        prevOffset = this.parseXRefStream(xrefOffset);
                        parseSuccess = true;
                    }
                } catch (e) {
                    console.warn('PDFDecrypt: XRef parsing failed at offset', xrefOffset, ':', e.message);
                    // Try to continue with other xref sections or fallback
                    break;
                }
                
                // Follow /Prev chain
                xrefOffset = prevOffset;
            }
            
            // If XRef parsing failed or found no objects, fallback to scanning
            // If XRef parsing failed or found too few objects, fallback to scanning
            if (!parseSuccess || this.xref.size === 0) {
                console.log('PDFDecrypt: XRef parsing incomplete, scanning for objects...');
                this.scanForObjects();
            }
            
            // Always ensure we have complete object list by scanning
            // XRef stream may have ended early
            const initialCount = this.xref.size;
            this.scanForObjects();
            if (this.xref.size > initialCount) {
                console.log('PDFDecrypt: Scanning found', this.xref.size - initialCount, 'additional objects');
            }
            
            console.log('PDFDecrypt: Parsed', this.xref.size, 'direct objects,', this.objectStreams.size, 'objects in streams');
        }
        
        /**
         * Fallback method: Scan through PDF to find objects
         */
        scanForObjects() {
            const objPattern = /(\d+)\s+(\d+)\s+obj/g;
            const pdfStr = Utils.bytesToString(this.data);
            let match;
            
            while ((match = objPattern.exec(pdfStr)) !== null) {
                const num = parseInt(match[1], 10);
                const gen = parseInt(match[2], 10);
                const offset = match.index;
                const key = `${num} ${gen}`;
                
                if (!this.xref.has(key)) {
                    this.xref.set(key, { offset, gen, type: 'n' });
                } else {
                    // Prefer scanned offsets when existing XRef offset is bogus
                    // (common when XRef stream was inflated without decrypting first)
                    const existing = this.xref.get(key);
                    if (!existing || typeof existing.offset !== 'number' ||
                        existing.offset < 0 || existing.offset >= this.data.length) {
                        this.xref.set(key, { offset, gen, type: 'n' });
                    }
                }
            }
            
            // Try to find trailer if not already parsed
            if (!this.trailer) {
                const trailerPos = pdfStr.lastIndexOf('trailer');
                if (trailerPos !== -1) {
                    this.pos = trailerPos + 7;
                    this.skipWhitespace();
                    try {
                        this.trailer = this.parseDictionary();
                    } catch (e) {
                        console.warn('PDFDecrypt: Could not parse trailer:', e.message);
                    }
                }
            }
            
            // If trailer exists but has no /Encrypt, check if XRef stream has it
            // Also look for /Encrypt directly in PDF (for hybrid PDFs)
            if (!this.trailer || !this.trailer['/Encrypt']) {
                this.findEncryptDictDirect(pdfStr);
            }
        }
        
        /**
         * Directly search for encryption dictionary in PDF
         */
        findEncryptDictDirect(pdfStr) {
            console.log('PDFDecrypt: Searching for encryption info directly in PDF...');
            
            // Prefer the last /Encrypt reference (trailer / latest incremental update).
            // On large PDFs this is near the end; first match may be stale or absent in head.
            let encryptObjNum = null;
            let encryptGen = null;
            const encryptRefRe = /\/Encrypt\s+(\d+)\s+(\d+)\s+R/g;
            let encryptRefMatch;
            while ((encryptRefMatch = encryptRefRe.exec(pdfStr)) !== null) {
                encryptObjNum = parseInt(encryptRefMatch[1], 10);
                encryptGen = parseInt(encryptRefMatch[2], 10);
            }

            if (encryptObjNum !== null) {
                console.log('PDFDecrypt: Found /Encrypt reference to object', encryptObjNum, encryptGen);
                
                if (!this.trailer) {
                    this.trailer = {};
                }
                this.trailer['/Encrypt'] = { ref: true, num: encryptObjNum, gen: encryptGen };
                
                // Make sure this object is in xref
                const key = `${encryptObjNum} ${encryptGen}`;
                if (!this.xref.has(key)) {
                    // Find the object (last occurrence wins for incremental updates)
                    const objPattern = new RegExp(`${encryptObjNum}\\s+${encryptGen}\\s+obj`, 'g');
                    let objMatch;
                    let lastIndex = -1;
                    while ((objMatch = objPattern.exec(pdfStr)) !== null) {
                        lastIndex = objMatch.index;
                    }
                    if (lastIndex !== -1) {
                        this.xref.set(key, { offset: lastIndex, gen: encryptGen, type: 'n' });
                        console.log('PDFDecrypt: Added encrypt object to xref at offset', lastIndex);
                    }
                }
            } else {
                // Check if /Encrypt exists without being a reference (inline or in XRef stream dict)
                // Look for standard security handler markers
                if (pdfStr.includes('/Filter/Standard') || pdfStr.includes('/Filter /Standard')) {
                    console.log('PDFDecrypt: Found /Filter /Standard - PDF appears encrypted');
                    // This PDF has encryption, we need to find the encrypt dict
                    // Look in XRef stream dictionaries
                    const xrefStreamMatch = pdfStr.match(/\/Type\s*\/XRef[\s\S]{0,500}\/Encrypt/);
                    if (xrefStreamMatch) {
                        console.log('PDFDecrypt: Encryption info is in XRef stream dictionary');
                    }
                }
            }
            
            // Also look for /ID array which is needed for encryption
            if (!this.trailer || !this.trailer['/ID']) {
                const idMatch = pdfStr.match(/\/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\]/);
                if (idMatch) {
                    if (!this.trailer) {
                        this.trailer = {};
                    }
                    this.trailer['/ID'] = [
                        Utils.hexToBytes(idMatch[1]),
                        Utils.hexToBytes(idMatch[2])
                    ];
                    console.log('PDFDecrypt: Found /ID array');
                }
            }
            
            // Look for /Root reference
            if (!this.trailer || !this.trailer['/Root']) {
                const rootMatch = pdfStr.match(/\/Root\s+(\d+)\s+(\d+)\s+R/);
                if (rootMatch) {
                    if (!this.trailer) {
                        this.trailer = {};
                    }
                    this.trailer['/Root'] = { ref: true, num: parseInt(rootMatch[1], 10), gen: parseInt(rootMatch[2], 10) };
                }
            }
        }

        parseXRefTable() {
            this.pos += 4; // Skip 'xref'
            this.skipWhitespace();

            while (true) {
                const start = this.parseNumber();
                if (isNaN(start)) break;
                
                this.skipWhitespace();
                const count = this.parseNumber();
                this.skipWhitespace();

                for (let i = 0; i < count; i++) {
                    const offset = this.parseNumber();
                    this.skipWhitespace();
                    const gen = this.parseNumber();
                    this.skipWhitespace();
                    const type = String.fromCharCode(this.data[this.pos++]);
                    this.skipWhitespace();

                    const key = `${start + i} ${gen}`;
                    // Only add if not already present (later xref entries take precedence)
                    if (type === 'n' && !this.xref.has(key)) {
                        this.xref.set(key, { offset, gen, type: 'n' });
                    }
                }
            }
            
            // Parse trailer for this xref section
            this.skipWhitespace();
            const trailerPos = this.findString('trailer', this.pos);
            if (trailerPos !== -1 && trailerPos < this.pos + 100) {
                this.pos = trailerPos + 7;
                this.skipWhitespace();
                const trailerDict = this.parseDictionary();
                
                // Store first trailer (most recent) as main trailer
                if (!this.trailer) {
                    this.trailer = trailerDict;
                }
                
                // Return /Prev offset if present
                return trailerDict['/Prev'] || null;
            }
            
            return null;
        }

        parseXRefStream(offset, decryptor = null) {
            this.pos = offset;
            this.skipWhitespace();
            
            // Parse object number (needed to decrypt the XRef stream itself)
            const objNum = this.parseNumber();
            this.skipWhitespace();
            const genNum = this.parseNumber();
            this.skipWhitespace();
            
            // Skip 'obj'
            this.pos += 3;
            this.skipWhitespace();
            
            // Parse dictionary (plaintext even when document is encrypted)
            const dict = this.parseDictionary();
            
            // Get stream data
            this.skipWhitespace();
            const streamPos = this.findString('stream', this.pos);
            if (streamPos === -1) {
                throw new Error('Cannot find stream keyword in XRef stream');
            }
            this.pos = streamPos + 6;
            if (this.data[this.pos] === 0x0D) this.pos++;
            if (this.data[this.pos] === 0x0A) this.pos++;

            const streamDataStart = this.pos;

            // Always locate endstream — Length alone is unreliable / may exclude bytes
            const endMarker = Utils.stringToBytes('endstream');
            let endstreamPos = -1;
            outerEnd: for (let i = streamDataStart; i <= this.data.length - endMarker.length; i++) {
                for (let j = 0; j < endMarker.length; j++) {
                    if (this.data[i + j] !== endMarker[j]) continue outerEnd;
                }
                endstreamPos = i;
                break;
            }
            if (endstreamPos === -1) {
                throw new Error('Cannot find endstream in XRef stream');
            }

            let dictLength = dict.Length || dict['/Length'];
            if (typeof dictLength === 'object' && dictLength && dictLength.ref) {
                // Indirect length — resolve if possible, else fall back to endstream
                try {
                    const lenObj = this.getObject(dictLength.num, dictLength.gen);
                    dictLength = (typeof lenObj === 'number') ? lenObj : null;
                } catch (e) {
                    dictLength = null;
                }
            }

            let streamLength = endstreamPos - streamDataStart;
            while (streamLength > 0 &&
                   (this.data[streamDataStart + streamLength - 1] === 0x0A ||
                    this.data[streamDataStart + streamLength - 1] === 0x0D)) {
                streamLength--;
            }

            // Prefer declared Length when it looks sane; otherwise use endstream span
            if (typeof dictLength === 'number' && dictLength > 0 &&
                dictLength <= streamLength && dictLength >= streamLength - 4) {
                streamLength = dictLength;
            }

            let streamData = this.data.slice(streamDataStart, streamDataStart + streamLength);

            // CRITICAL: In encrypted PDFs the XRef *stream bytes* are encrypted.
            // Decrypt before FlateDecode, otherwise entries/offsets are garbage.
            if (decryptor && decryptor.isEncrypted()) {
                try {
                    const before = streamData.length;
                    streamData = decryptor.decryptStream(streamData, objNum, genNum);
                    console.log('PDFDecrypt: Decrypted XRef stream obj', objNum,
                        'gen', genNum, 'in=', before, 'out=', streamData.length);
                } catch (e) {
                    console.warn('PDFDecrypt: Failed to decrypt XRef stream:', e.message);
                }
            }
            
            // Decompress (Filter may be a name or an array)
            let decoded = streamData;
            let filter = dict.Filter || dict['/Filter'];
            if (Array.isArray(filter)) {
                filter = filter[0];
            }
            if (filter === '/FlateDecode' || filter === 'FlateDecode') {
                try {
                    decoded = Inflate.inflate(streamData);
                } catch (inflateError) {
                    console.error('PDFDecrypt: Failed to inflate XRef stream:', inflateError.message);
                    let inflated = null;
                    for (let trim = 1; trim <= 32; trim++) {
                        try {
                            inflated = Inflate.inflate(streamData.slice(0, -trim));
                            console.log('PDFDecrypt: Inflate succeeded after trimming', trim, 'bytes');
                            break;
                        } catch (e) {}
                    }
                    if (!inflated) {
                        throw new Error('Failed to decompress XRef stream: ' + inflateError.message);
                    }
                    decoded = inflated;
                }
            }

            // Undo PNG/TIFF predictors
            let decodeParms = dict.DecodeParms || dict['/DecodeParms'] ||
                              dict.DP || dict['/DP'];
            if (Array.isArray(decodeParms)) {
                decodeParms = decodeParms[0];
            }
            if (decodeParms && typeof decodeParms === 'object') {
                decoded = StreamPredictor.apply(decoded, decodeParms);
            }
            
            const w = dict.W || dict['/W'];
            const size = dict.Size || dict['/Size'];
            const index = dict.Index || dict['/Index'] || [0, size];
            
            if (!w || !Array.isArray(w) || w.length < 3) {
                throw new Error('Invalid /W array in XRef stream');
            }

            const entrySize = (w[0] || 0) + (w[1] || 0) + (w[2] || 0);
            let expectedEntries = 0;
            for (let i = 0; i < index.length; i += 2) {
                expectedEntries += index[i + 1] || 0;
            }
            const expectedBytes = expectedEntries * entrySize;
            console.log('PDFDecrypt: XRef stream decoded length=', decoded.length,
                'expected=', expectedBytes, 'entrySize=', entrySize, 'Size=', size,
                'Index=', Array.isArray(index) ? index.join(',') : index);

            // If still short and no DecodeParms, try PNG Up predictor with Columns=entrySize
            if (decoded.length < expectedBytes && decoded.length > expectedBytes * 0.5) {
                const maybe = StreamPredictor.apply(decoded, {
                    '/Predictor': 12,
                    '/Columns': entrySize
                });
                if (maybe.length >= expectedBytes || maybe.length > decoded.length) {
                    console.log('PDFDecrypt: Applied fallback PNG predictor, out=', maybe.length);
                    decoded = maybe;
                }
            }

            let endedEarly = false;
            let pos = 0;
            for (let i = 0; i < index.length; i += 2) {
                const start = index[i];
                const count = index[i + 1];
                
                for (let j = 0; j < count; j++) {
                    if (pos + entrySize > decoded.length) {
                        console.warn('PDFDecrypt: XRef stream data ended early at object', start + j,
                            '(decoded length ' + decoded.length + ', pos ' + pos + ')');
                        endedEarly = true;
                        break;
                    }
                    
                    let type = 1;
                    if (w[0] > 0) {
                        type = 0;
                        for (let k = 0; k < w[0]; k++) {
                            type = (type << 8) | decoded[pos++];
                        }
                    }
                    
                    let field2 = 0;
                    for (let k = 0; k < w[1]; k++) {
                        field2 = (field2 << 8) | decoded[pos++];
                    }
                    
                    let field3 = 0;
                    for (let k = 0; k < w[2]; k++) {
                        field3 = (field3 << 8) | decoded[pos++];
                    }
                    
                    const objNumEntry = start + j;
                    const key = `${objNumEntry} 0`;
                    
                    if (type === 0) {
                        // free
                    } else if (type === 1) {
                        // Only accept offsets inside the file
                        if (field2 >= 0 && field2 < this.data.length) {
                            this.xref.set(key, { offset: field2, gen: field3, type: 'n' });
                        } else {
                            console.warn('PDFDecrypt: Ignoring out-of-range XRef offset', field2,
                                'for object', objNumEntry);
                        }
                    } else if (type === 2) {
                        // object stream — stream obj num must be plausible
                        if (field2 > 0 && field2 < (size || this.data.length)) {
                            this.objectStreams.set(key, { streamObjNum: field2, indexInStream: field3 });
                            // Ensure we don't keep a bogus direct offset for this object
                            this.xref.delete(key);
                        }
                    }
                }
                if (endedEarly) break;
            }
            
            if (!this.trailer) {
                this.trailer = dict;
                console.log('PDFDecrypt: XRef stream dictionary keys:', Object.keys(dict).join(', '));
                if (dict['/Encrypt']) {
                    console.log('PDFDecrypt: Found /Encrypt in XRef stream dict');
                }
                if (dict['/ID']) {
                    console.log('PDFDecrypt: Found /ID in XRef stream dict');
                }
            }

            this._lastXRefStreamEndedEarly = endedEarly;
            this._lastXRefStreamOffset = offset;
            this._lastXRefStreamObjNum = objNum;
            
            return dict['/Prev'] || null;
        }

        /**
         * After the password/key is known, re-parse the XRef stream with decryption.
         * Encrypted PDFs store compressed XRef bytes encrypted — first-pass inflate is wrong.
         */
        reparseXRefWithDecryptor(decryptor) {
            if (!decryptor || !decryptor.isEncrypted()) return false;
            if (typeof this._lastXRefStreamOffset !== 'number') {
                // Try to locate startxref again
                const startxrefPos = this.findStringReverse('startxref');
                if (startxrefPos === -1) return false;
                this.pos = startxrefPos + 9;
                this.skipWhitespace();
                this._lastXRefStreamOffset = this.parseNumber();
            }

            console.log('PDFDecrypt: Re-parsing XRef stream with decryption at', this._lastXRefStreamOffset);

            // Keep trailer; rebuild object maps from decrypted stream
            const savedTrailer = this.trailer;
            this.xref.clear();
            this.objectStreams.clear();

            try {
                this.parseXRefStream(this._lastXRefStreamOffset, decryptor);
            } catch (e) {
                console.warn('PDFDecrypt: Re-parse XRef with decrypt failed:', e.message);
            }

            if (savedTrailer && !this.trailer) this.trailer = savedTrailer;
            else if (savedTrailer) this.trailer = savedTrailer; // keep original trailer refs

            // Fill gaps / fix any remaining bad offsets via scan
            this.scanForObjects();

            // Drop bogus object-stream references
            for (const [key, info] of Array.from(this.objectStreams.entries())) {
                const sKey = `${info.streamObjNum} 0`;
                const sEntry = this.xref.get(sKey);
                if (!sEntry || sEntry.offset < 0 || sEntry.offset >= this.data.length) {
                    console.warn('PDFDecrypt: Dropping invalid object-stream ref', key, info);
                    this.objectStreams.delete(key);
                }
            }

            console.log('PDFDecrypt: After decrypted XRef reparse:',
                this.xref.size, 'direct objects,',
                this.objectStreams.size, 'objects in streams',
                'endedEarly=', !!this._lastXRefStreamEndedEarly);
            return !this._lastXRefStreamEndedEarly;
        }

        parseTrailer() {
            if (this.trailer) return; // Already parsed from xref stream
            
            const trailerPos = this.findStringReverse('trailer');
            if (trailerPos === -1) {
                throw new Error('Cannot find trailer');
            }

            this.pos = trailerPos + 7;
            this.skipWhitespace();
            this.trailer = this.parseDictionary();
        }

        skipWhitespace() {
            while (this.pos < this.data.length) {
                const c = this.data[this.pos];
                if (c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D || c === 0x00) {
                    this.pos++;
                } else if (c === 0x25) { // Comment
                    while (this.pos < this.data.length && this.data[this.pos] !== 0x0A && this.data[this.pos] !== 0x0D) {
                        this.pos++;
                    }
                } else {
                    break;
                }
            }
        }

        parseNumber() {
            this.skipWhitespace();
            let str = '';
            while (this.pos < this.data.length) {
                const c = this.data[this.pos];
                if ((c >= 0x30 && c <= 0x39) || c === 0x2E || c === 0x2D || c === 0x2B) {
                    str += String.fromCharCode(c);
                    this.pos++;
                } else {
                    break;
                }
            }
            return parseFloat(str);
        }

        parseString() {
            const result = [];
            let parenDepth = 1;
            this.pos++; // Skip opening (
            
            while (this.pos < this.data.length && parenDepth > 0) {
                const c = this.data[this.pos++];
                if (c === 0x28) { // (
                    parenDepth++;
                    result.push(c);
                } else if (c === 0x29) { // )
                    parenDepth--;
                    if (parenDepth > 0) result.push(c);
                } else if (c === 0x5C) { // Backslash escape
                    const next = this.data[this.pos++];
                    if (next === 0x6E) result.push(0x0A); // \n
                    else if (next === 0x72) result.push(0x0D); // \r
                    else if (next === 0x74) result.push(0x09); // \t
                    else if (next === 0x62) result.push(0x08); // \b
                    else if (next === 0x66) result.push(0x0C); // \f
                    else if (next >= 0x30 && next <= 0x37) { // Octal
                        let octal = next - 0x30;
                        for (let i = 0; i < 2; i++) {
                            if (this.data[this.pos] >= 0x30 && this.data[this.pos] <= 0x37) {
                                octal = (octal << 3) | (this.data[this.pos++] - 0x30);
                            }
                        }
                        result.push(octal);
                    } else {
                        result.push(next);
                    }
                } else {
                    result.push(c);
                }
            }
            
            return new Uint8Array(result);
        }

        parseHexString() {
            this.pos++; // Skip <
            let hex = '';
            while (this.pos < this.data.length) {
                const c = this.data[this.pos++];
                if (c === 0x3E) break; // >
                if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)) {
                    hex += String.fromCharCode(c);
                }
            }
            if (hex.length % 2) hex += '0';
            return Utils.hexToBytes(hex);
        }

        parseName() {
            this.pos++; // Skip /
            let name = '/';
            while (this.pos < this.data.length) {
                const c = this.data[this.pos];
                if (c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D || 
                    c === 0x2F || c === 0x5B || c === 0x5D || c === 0x3C || 
                    c === 0x3E || c === 0x28 || c === 0x29 || c === 0x7B || c === 0x7D) {
                    break;
                }
                if (c === 0x23) { // Hex escape
                    const hex = String.fromCharCode(this.data[this.pos + 1], this.data[this.pos + 2]);
                    name += String.fromCharCode(parseInt(hex, 16));
                    this.pos += 3;
                } else {
                    name += String.fromCharCode(c);
                    this.pos++;
                }
            }
            return name;
        }

        parseArray() {
            this.pos++; // Skip [
            const arr = [];
            while (this.pos < this.data.length) {
                this.skipWhitespace();
                if (this.data[this.pos] === 0x5D) { // ]
                    this.pos++;
                    break;
                }
                arr.push(this.parseValue());
            }
            return arr;
        }

        parseDictionary() {
            this.pos += 2; // Skip <<
            const dict = {};
            while (this.pos < this.data.length) {
                this.skipWhitespace();
                if (this.data[this.pos] === 0x3E && this.data[this.pos + 1] === 0x3E) { // >>
                    this.pos += 2;
                    break;
                }
                const key = this.parseName();
                this.skipWhitespace();
                const value = this.parseValue();
                dict[key] = value;
            }
            return dict;
        }

        parseValue() {
            this.skipWhitespace();
            const c = this.data[this.pos];
            const c2 = this.data[this.pos + 1];

            if (c === 0x3C && c2 === 0x3C) { // <<
                return this.parseDictionary();
            } else if (c === 0x3C) { // <
                return this.parseHexString();
            } else if (c === 0x28) { // (
                return this.parseString();
            } else if (c === 0x2F) { // /
                return this.parseName();
            } else if (c === 0x5B) { // [
                return this.parseArray();
            } else if (c === 0x74 || c === 0x66) { // true/false
                if (String.fromCharCode(...this.data.slice(this.pos, this.pos + 4)) === 'true') {
                    this.pos += 4;
                    return true;
                } else if (String.fromCharCode(...this.data.slice(this.pos, this.pos + 5)) === 'false') {
                    this.pos += 5;
                    return false;
                }
            } else if (c === 0x6E) { // null
                if (String.fromCharCode(...this.data.slice(this.pos, this.pos + 4)) === 'null') {
                    this.pos += 4;
                    return null;
                }
            } else if ((c >= 0x30 && c <= 0x39) || c === 0x2D || c === 0x2B || c === 0x2E) {
                // Number or reference
                const startPos = this.pos;
                const num1 = this.parseNumber();
                this.skipWhitespace();
                
                // Check if it's an indirect reference (num gen R)
                const savedPos = this.pos;
                if (this.data[this.pos] >= 0x30 && this.data[this.pos] <= 0x39) {
                    const num2 = this.parseNumber();
                    this.skipWhitespace();
                    if (this.data[this.pos] === 0x52) { // R
                        this.pos++;
                        return { ref: true, num: num1, gen: num2 };
                    }
                }
                this.pos = savedPos;
                return num1;
            }

            throw new Error(`Unexpected character at position ${this.pos}: ${String.fromCharCode(c)}`);
        }

        getObject(num, gen = 0) {
            const key = `${num} ${gen}`;
            
            if (this.objects.has(key)) {
                return this.objects.get(key);
            }

            const xrefEntry = this.xref.get(key);
            if (!xrefEntry) {
                return null;
            }

            this.pos = xrefEntry.offset;
            this.skipWhitespace();
            
            // Parse "num gen obj"
            this.parseNumber(); // num
            this.skipWhitespace();
            this.parseNumber(); // gen
            this.skipWhitespace();
            
            // Skip "obj"
            this.pos += 3;
            this.skipWhitespace();

            const obj = this.parseValue();
            this.objects.set(key, obj);
            
            return obj;
        }

        getStream(num, gen = 0) {
            const obj = this.getObject(num, gen);
            if (!obj) return null;

            const xrefEntry = this.xref.get(`${num} ${gen}`);
            this.pos = xrefEntry.offset;
            
            // Find stream keyword
            const streamPos = this.findString('stream', this.pos);
            if (streamPos === -1) return null;

            this.pos = streamPos + 6;
            if (this.data[this.pos] === 0x0D) this.pos++;
            if (this.data[this.pos] === 0x0A) this.pos++;

            let length = obj['/Length'];
            if (typeof length === 'object' && length.ref) {
                length = this.getObject(length.num, length.gen);
            }

            return {
                dict: obj,
                data: this.data.slice(this.pos, this.pos + length)
            };
        }

        getEncryptDict() {
            // If encryptDict was set directly (from raw extraction), return it
            if (this.encryptDict && this.isValidEncryptDict(this.encryptDict)) {
                console.log('PDFDecrypt: Using directly set encryptDict');
                return this.encryptDict;
            }
            
            if (!this.trailer || !this.trailer['/Encrypt']) {
                // Try to find it directly
                this.findEncryptDictDirect(Utils.bytesToString(this.data));
            }
            
            if (this.trailer && this.trailer['/Encrypt']) {
                const encryptRef = this.trailer['/Encrypt'];
                if (encryptRef && encryptRef.ref) {
                    // Prefer a content-based parse: incomplete XRef streams on large PDFs
                    // often have wrong offsets, which yields a bogus encrypt dict and
                    // false "Invalid password" errors.
                    let encryptDict = this.parseEncryptObjectBinary(encryptRef.num, encryptRef.gen);
                    if (this.isValidEncryptDict(encryptDict)) {
                        this.encryptDict = encryptDict;
                        console.log('PDFDecrypt: Loaded encrypt dict via binary parse, V=',
                            encryptDict['/V'], 'R=', encryptDict['/R'],
                            'O=', encryptDict['/O'] ? encryptDict['/O'].length : 0,
                            'U=', encryptDict['/U'] ? encryptDict['/U'].length : 0,
                            'Length=', encryptDict['/Length'],
                            'EncryptMetadata=', encryptDict['/EncryptMetadata']);
                        return encryptDict;
                    }

                    encryptDict = this.getObject(encryptRef.num, encryptRef.gen);
                    if (this.isValidEncryptDict(encryptDict)) {
                        this.encryptDict = encryptDict;
                        return encryptDict;
                    }
                    
                    encryptDict = this.parseObjectDirectly(encryptRef.num, encryptRef.gen);
                    if (this.isValidEncryptDict(encryptDict)) {
                        this.encryptDict = encryptDict;
                        return encryptDict;
                    }
                } else if (this.isValidEncryptDict(encryptRef)) {
                    // Inline encrypt dictionary
                    this.encryptDict = encryptRef;
                    return encryptRef;
                }
            }

            // Last resort: locate /Filter /Standard in binary
            const fallback = this.findStandardEncryptDictBinary();
            if (this.isValidEncryptDict(fallback)) {
                this.encryptDict = fallback;
                console.log('PDFDecrypt: Loaded encrypt dict via Standard-filter binary scan');
                return fallback;
            }

            return null;
        }

        isValidEncryptDict(dict) {
            if (!dict || typeof dict !== 'object' || dict.ref) return false;
            const filter = dict['/Filter'];
            const hasFilter = filter === '/Standard' || filter === 'Standard';
            const hasOU = dict['/O'] != null && dict['/U'] != null;
            return hasFilter && hasOU;
        }

        /**
         * Parse object N G from binary by scanning for "N G obj" (last match)
         * and reading the following value — avoids corrupt XRef offsets.
         */
        parseEncryptObjectBinary(num, gen) {
            const needle = Utils.stringToBytes(`${num} ${gen} obj`);
            let found = -1;
            outer: for (let i = 0; i <= this.data.length - needle.length; i++) {
                for (let j = 0; j < needle.length; j++) {
                    if (this.data[i + j] !== needle[j]) continue outer;
                }
                // Ensure this isn't a longer number prefix (e.g. 12 matching 2)
                if (i > 0) {
                    const prev = this.data[i - 1];
                    if (prev >= 0x30 && prev <= 0x39) continue;
                }
                found = i;
            }
            if (found === -1) return null;

            this.pos = found + needle.length;
            this.skipWhitespace();
            try {
                return this.parseValue();
            } catch (e) {
                console.warn('PDFDecrypt: parseEncryptObjectBinary failed:', e.message);
                return null;
            }
        }

        /**
         * Find the dictionary that contains /Filter /Standard by binary scan.
         */
        findStandardEncryptDictBinary() {
            const patterns = [
                Utils.stringToBytes('/Filter/Standard'),
                Utils.stringToBytes('/Filter /Standard')
            ];
            let filterPos = -1;
            for (const pat of patterns) {
                for (let i = this.data.length - pat.length; i >= 0; i--) {
                    let ok = true;
                    for (let j = 0; j < pat.length; j++) {
                        if (this.data[i + j] !== pat[j]) { ok = false; break; }
                    }
                    if (ok) { filterPos = i; break; }
                }
                if (filterPos !== -1) break;
            }
            if (filterPos === -1) return null;

            // Walk back to the start of the enclosing << dictionary
            let dictStart = -1;
            for (let i = filterPos; i >= 1; i--) {
                if (this.data[i - 1] === 0x3C && this.data[i] === 0x3C) {
                    dictStart = i - 1;
                    break;
                }
            }
            if (dictStart === -1) return null;

            const saved = this.pos;
            this.pos = dictStart;
            try {
                const dict = this.parseDictionary();
                this.pos = saved;
                return dict;
            } catch (e) {
                this.pos = saved;
                console.warn('PDFDecrypt: findStandardEncryptDictBinary failed:', e.message);
                return null;
            }
        }
        
        /**
         * Parse an object directly by searching for it in the PDF
         */
        parseObjectDirectly(num, gen) {
            return this.parseEncryptObjectBinary(num, gen);
        }

        getIDArray() {
            // If idArray was set directly (from raw extraction), return it
            if (this.idArray) {
                console.log('PDFDecrypt: Using directly set idArray');
                return this.normalizeIDArray(this.idArray);
            }
            
            if (this.trailer && this.trailer['/ID']) {
                const normalized = this.normalizeIDArray(this.trailer['/ID']);
                if (normalized) {
                    this.idArray = normalized;
                    return normalized;
                }
            }

            // Prefer the last /ID in the file (current trailer)
            const pdfStr = Utils.bytesToString(this.data);
            let lastMatch = null;
            const idHexRe = /\/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\]/g;
            let m;
            while ((m = idHexRe.exec(pdfStr)) !== null) {
                lastMatch = m;
            }
            if (lastMatch) {
                this.idArray = [
                    Utils.hexToBytes(lastMatch[1]),
                    Utils.hexToBytes(lastMatch[2])
                ];
                return this.idArray;
            }

            return null;
        }

        normalizeIDArray(id) {
            if (!id) return null;
            if (!Array.isArray(id) || id.length < 1) return null;
            const out = [];
            for (let i = 0; i < id.length; i++) {
                let entry = id[i];
                if (entry instanceof Uint8Array) {
                    out.push(entry);
                } else if (typeof entry === 'string') {
                    out.push(Utils.stringToBytes(entry));
                } else if (Array.isArray(entry)) {
                    out.push(new Uint8Array(entry));
                } else {
                    return null;
                }
            }
            return out;
        }

        /**
         * Extract an object from an object stream
         * @param {number} objNum - The object number to extract
         * @param {Object} decryptor - The decryptor instance (needed to decrypt the object stream)
         * @returns {Object} - The extracted object data as bytes
         */
        getObjectFromStream(objNum, decryptor) {
            const key = `${objNum} 0`;
            const streamInfo = this.objectStreams.get(key);
            if (!streamInfo) {
                return null;
            }
            
            const { streamObjNum, indexInStream } = streamInfo;
            
            // Get the object stream
            const streamObj = this.getObject(streamObjNum, 0);
            if (!streamObj || streamObj['/Type'] !== '/ObjStm') {
                console.warn('PDFDecrypt: Object stream', streamObjNum, 'not found or invalid type');
                return null;
            }
            
            // Get the stream data
            const streamData = this.getStream(streamObjNum, 0);
            if (!streamData) {
                return null;
            }
            
            // Decrypt the stream if encrypted
            let decodedData = streamData.data;
            if (decryptor && decryptor.isEncrypted()) {
                try {
                    decodedData = decryptor.decryptStream(streamData.data, streamObjNum, 0);
                } catch (e) {
                    console.warn('PDFDecrypt: Failed to decrypt object stream', streamObjNum, e.message);
                }
            }
            
            // Decompress if needed
            let filter = streamObj['/Filter'];
            if (Array.isArray(filter)) filter = filter[0];
            if (filter === '/FlateDecode' || filter === 'FlateDecode') {
                try {
                    decodedData = Inflate.inflate(decodedData);
                } catch (e) {
                    console.warn('PDFDecrypt: Failed to decompress object stream', streamObjNum, e.message);
                    return null;
                }
            }
            
            // Parse the object stream structure
            const n = streamObj['/N']; // Number of objects
            const first = streamObj['/First']; // Offset of first object
            
            // Parse the index (pairs of objNum, offset)
            const indexData = Utils.bytesToString(decodedData.slice(0, first));
            const indexParts = indexData.trim().split(/\s+/).map(Number);
            
            // Find our object in the index
            let objectOffset = -1;
            let nextOffset = decodedData.length;
            
            for (let i = 0; i < indexParts.length; i += 2) {
                const indexObjNum = indexParts[i];
                const offset = indexParts[i + 1];
                
                if (indexObjNum === objNum) {
                    objectOffset = first + offset;
                    // Get next offset for length calculation
                    if (i + 2 < indexParts.length) {
                        nextOffset = first + indexParts[i + 3];
                    }
                    break;
                }
            }
            
            if (objectOffset === -1) {
                console.warn('PDFDecrypt: Object', objNum, 'not found in object stream', streamObjNum);
                return null;
            }
            
            // Extract the object bytes
            const objectBytes = decodedData.slice(objectOffset, nextOffset);
            return {
                bytes: objectBytes,
                streamObjNum: streamObjNum,
                indexInStream: indexInStream
            };
        }

        /**
         * Get all objects stored in a specific object stream (for rebuilding)
         */
        extractAllFromObjectStream(streamObjNum, decryptor) {
            // Get the object stream
            const streamObj = this.getObject(streamObjNum, 0);
            if (!streamObj || streamObj['/Type'] !== '/ObjStm') {
                return [];
            }
            
            // Get the stream data
            const streamData = this.getStream(streamObjNum, 0);
            if (!streamData) {
                return [];
            }
            
            // Decrypt the stream if encrypted
            let decodedData = streamData.data;
            if (decryptor && decryptor.isEncrypted()) {
                try {
                    decodedData = decryptor.decryptStream(streamData.data, streamObjNum, 0);
                } catch (e) {
                    console.warn('PDFDecrypt: Failed to decrypt object stream', streamObjNum, e.message);
                    return [];
                }
            }
            
            // Decompress if needed
            let filter = streamObj['/Filter'];
            if (Array.isArray(filter)) filter = filter[0];
            if (filter === '/FlateDecode' || filter === 'FlateDecode') {
                try {
                    decodedData = Inflate.inflate(decodedData);
                } catch (e) {
                    console.warn('PDFDecrypt: Failed to decompress object stream', streamObjNum);
                    return [];
                }
            }
            
            // Parse the object stream structure
            const n = streamObj['/N']; // Number of objects
            const first = streamObj['/First']; // Offset of first object
            
            // Parse the index (pairs of objNum, offset)
            const indexData = Utils.bytesToString(decodedData.slice(0, first));
            const indexParts = indexData.trim().split(/\s+/).map(Number);
            
            const objects = [];
            for (let i = 0; i < indexParts.length; i += 2) {
                const objNum = indexParts[i];
                const offset = indexParts[i + 1];
                const absoluteOffset = first + offset;
                
                // Get next offset for length calculation
                let nextOffset = decodedData.length;
                if (i + 2 < indexParts.length) {
                    nextOffset = first + indexParts[i + 3];
                }
                
                const objectBytes = decodedData.slice(absoluteOffset, nextOffset);
                objects.push({
                    objNum: objNum,
                    gen: 0,
                    bytes: objectBytes
                });
            }
            
            return objects;
        }
    }

    // ============================================
    // SECTION 8: PDF DECRYPTION ENGINE
    // ============================================
    
    class PDFDecryptor {
        constructor(parser, password) {
            this.parser = parser;
            this.password = password;
            this.encryptDict = parser.getEncryptDict();
            this.idArray = parser.getIDArray();
            this.encryptionKey = null;
            
            // Standard padding for PDF encryption
            this.passwordPadding = new Uint8Array([
                0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
                0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
                0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
                0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
            ]);
        }

        isEncrypted() {
            return this.encryptDict !== null;
        }

        getEncryptionInfo() {
            if (!this.encryptDict) return null;

            const V = this.encryptDict['/V'] || 0;
            const R = this.encryptDict['/R'] || 2;
            // Key length in bits. Missing /Length defaults to 40 for V1, 128 for V>=2.
            let Length = this.encryptDict['/Length'];
            if (typeof Length !== 'number' || !Length) {
                Length = V >= 2 ? 128 : 40;
            }
            
            return {
                V: V,
                R: R,
                Length: Length,
                P: this.encryptDict['/P'] || 0,
                CF: this.encryptDict['/CF'],
                StmF: this.encryptDict['/StmF'],
                StrF: this.encryptDict['/StrF'],
                EncryptMetadata: this.encryptDict['/EncryptMetadata'] !== false
            };
        }

        padPassword(password) {
            const bytes = Utils.stringToBytes(password || '');
            const padded = new Uint8Array(32);
            padded.set(bytes.slice(0, 32));
            if (bytes.length < 32) {
                padded.set(this.passwordPadding.slice(0, 32 - bytes.length), bytes.length);
            }
            return padded;
        }

        /**
         * Ensure O/U entries are Uint8Array (parsers may yield arrays).
         */
        asBytes(value) {
            if (value instanceof Uint8Array) return value;
            if (Array.isArray(value)) return new Uint8Array(value);
            if (typeof value === 'string') return Utils.stringToBytes(value);
            return null;
        }

        computeEncryptionKey() {
            const info = this.getEncryptionInfo();
            const keyLength = (info.Length || 40) / 8;
            
            console.log('PDFDecrypt: Encryption info:', info);
            
            if (info.V >= 5) {
                return this.computeEncryptionKeyV5();
            }

            // Try as user password first, then as owner password
            if (this.tryComputeKeyAsUser(this.padPassword(this.password), keyLength, info)) {
                console.log('PDFDecrypt: Key derived via user-password algorithm');
                return this.encryptionKey;
            }

            const recoveredUserPad = this.recoverUserPadFromOwnerPassword(keyLength, info);
            if (recoveredUserPad && this.tryComputeKeyAsUser(recoveredUserPad, keyLength, info)) {
                console.log('PDFDecrypt: Key derived via owner-password algorithm');
                return this.encryptionKey;
            }

            // Keep last attempted user-password key for callers; verification will fail
            this.tryComputeKeyAsUser(this.padPassword(this.password), keyLength, info);
            return this.encryptionKey;
        }

        /**
         * Algorithm 3.2 — compute file encryption key from padded user password.
         * Returns true if the resulting key authenticates against /U.
         */
        tryComputeKeyAsUser(paddedUserPassword, keyLength, info) {
            const o = this.asBytes(this.encryptDict['/O']);
            const u = this.asBytes(this.encryptDict['/U']);
            if (!o || !u || !this.idArray || !this.idArray[0]) {
                console.warn('PDFDecrypt: Missing O/U/ID for key computation',
                    { o: !!o, u: !!u, id: !!(this.idArray && this.idArray[0]) });
                return false;
            }

            const p = info.P | 0;
            const id = this.idArray[0];
            
            let input = Utils.concatBytes(
                paddedUserPassword,
                o,
                new Uint8Array([
                    p & 0xFF,
                    (p >> 8) & 0xFF,
                    (p >> 16) & 0xFF,
                    (p >> 24) & 0xFF
                ]),
                id
            );
            
            // PDF 1.7 Algorithm 3.2 step 6:
            // Append 4 bytes of 0xFF only when EncryptMetadata is FALSE.
            // Absent EncryptMetadata defaults to TRUE — do NOT append.
            if (info.R >= 4 && this.encryptDict['/EncryptMetadata'] === false) {
                input = Utils.concatBytes(input, new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]));
            }
            
            let hash = MD5.hash(input);
            
            if (info.R >= 3) {
                for (let i = 0; i < 50; i++) {
                    hash = MD5.hash(hash.slice(0, keyLength));
                }
            }
            
            this.encryptionKey = hash.slice(0, keyLength);
            return this.authenticateUserKey(this.encryptionKey, u, info);
        }

        /**
         * Algorithm 3.5 — verify file key against /U (first 16 bytes for R>=3).
         */
        authenticateUserKey(fileKey, u, info) {
            let computedU;
            
            if (info.R >= 3) {
                const id = this.idArray[0];
                const input = Utils.concatBytes(this.passwordPadding, id);
                let hash = MD5.hash(input);
                computedU = RC4.crypt(fileKey, hash);
                
                for (let i = 1; i <= 19; i++) {
                    const xorKey = new Uint8Array(fileKey.length);
                    for (let j = 0; j < fileKey.length; j++) {
                        xorKey[j] = fileKey[j] ^ i;
                    }
                    computedU = RC4.crypt(xorKey, computedU);
                }
                
                for (let i = 0; i < 16; i++) {
                    if (computedU[i] !== u[i]) return false;
                }
                return true;
            }

            computedU = RC4.crypt(fileKey, this.passwordPadding);
            for (let i = 0; i < 32; i++) {
                if (computedU[i] !== u[i]) return false;
            }
            return true;
        }

        /**
         * Algorithm 3.7 / 3.3 — treat supplied password as owner password and
         * recover the padded user password from /O.
         */
        recoverUserPadFromOwnerPassword(keyLength, info) {
            const o = this.asBytes(this.encryptDict['/O']);
            if (!o) return null;

            let hash = MD5.hash(this.padPassword(this.password));
            if (info.R >= 3) {
                for (let i = 0; i < 50; i++) {
                    hash = MD5.hash(hash);
                }
            }
            const ownerKey = hash.slice(0, keyLength);

            let userPad = new Uint8Array(o);
            if (info.R >= 3) {
                for (let i = 19; i >= 0; i--) {
                    const xorKey = new Uint8Array(ownerKey.length);
                    for (let j = 0; j < ownerKey.length; j++) {
                        xorKey[j] = ownerKey[j] ^ i;
                    }
                    userPad = RC4.crypt(xorKey, userPad);
                }
            } else {
                userPad = RC4.crypt(ownerKey, userPad);
            }

            return userPad.slice(0, 32);
        }

        computeEncryptionKeyV5() {
            // AES-256 encryption (PDF 2.0)
            const u = this.asBytes(this.encryptDict['/U']);
            const ue = this.asBytes(this.encryptDict['/UE']);
            const o = this.asBytes(this.encryptDict['/O']);
            const oe = this.asBytes(this.encryptDict['/OE']);
            
            const passwordBytes = Utils.stringToBytes(this.password || '');
            const truncated = passwordBytes.slice(0, 127);

            // Try user password (U/UE)
            if (u && ue && u.length >= 48) {
                const validationSalt = u.slice(32, 40);
                const keySalt = u.slice(40, 48);
                const validationHash = SHA256.hash(Utils.concatBytes(truncated, validationSalt));
                const uHash = u.slice(0, 32);
                let valid = true;
                for (let i = 0; i < 32; i++) {
                    if (validationHash[i] !== uHash[i]) { valid = false; break; }
                }
                if (valid) {
                    const keyHash = SHA256.hash(Utils.concatBytes(truncated, keySalt));
                    const iv = new Uint8Array(16); // All zeros for UE decryption
                    this.encryptionKey = AES.decryptCBCNoPad(keyHash, iv, ue).slice(0, 32);
                    return this.encryptionKey;
                }
            }

            // Try owner password (O/OE) — hash includes U
            if (o && oe && u && o.length >= 48) {
                const validationSalt = o.slice(32, 40);
                const keySalt = o.slice(40, 48);
                const validationHash = SHA256.hash(Utils.concatBytes(truncated, validationSalt, u));
                const oHash = o.slice(0, 32);
                let valid = true;
                for (let i = 0; i < 32; i++) {
                    if (validationHash[i] !== oHash[i]) { valid = false; break; }
                }
                if (valid) {
                    const keyHash = SHA256.hash(Utils.concatBytes(truncated, keySalt, u));
                    const iv = new Uint8Array(16);
                    this.encryptionKey = AES.decryptCBCNoPad(keyHash, iv, oe).slice(0, 32);
                    return this.encryptionKey;
                }
            }

            throw new Error('Invalid password');
        }

        verifyPassword() {
            if (!this.encryptDict) return true; // Not encrypted
            
            const info = this.getEncryptionInfo();
            
            try {
                if (!this.idArray || !this.idArray[0]) {
                    this.idArray = this.parser.getIDArray();
                }
                if ((!this.idArray || !this.idArray[0]) && info.V < 5) {
                    console.error('PDFDecrypt: Cannot verify password — missing /ID');
                    return false;
                }

                console.log('PDFDecrypt: Verifying password, V=', info.V, 'R=', info.R,
                    'Length=', info.Length, 'P=', info.P,
                    'EncryptMetadata=', info.EncryptMetadata,
                    'Olen=', this.encryptDict['/O'] ? this.asBytes(this.encryptDict['/O']).length : 0,
                    'Ulen=', this.encryptDict['/U'] ? this.asBytes(this.encryptDict['/U']).length : 0,
                    'IDlen=', this.idArray && this.idArray[0] ? this.idArray[0].length : 0);

                this.encryptionKey = null;

                if (info.V >= 5) {
                    this.computeEncryptionKeyV5();
                    return true;
                }

                const keyLength = (info.Length || 40) / 8;

                // User password
                if (this.tryComputeKeyAsUser(this.padPassword(this.password), keyLength, info)) {
                    console.log('PDFDecrypt: Password valid (user)');
                    return true;
                }

                // Owner password
                const recoveredUserPad = this.recoverUserPadFromOwnerPassword(keyLength, info);
                if (recoveredUserPad && this.tryComputeKeyAsUser(recoveredUserPad, keyLength, info)) {
                    console.log('PDFDecrypt: Password valid (owner)');
                    return true;
                }

                console.log('PDFDecrypt: Password did not match user or owner');
                return false;
            } catch (e) {
                console.error('PDFDecrypt: Password verification failed:', e);
                return false;
            }
        }

        /**
         * Resolve /StmF or /StrF to an actual crypt method (/AESV2, /V2, /None, ...).
         * Many PDFs use /StmF /StdCF with /CF << /StdCF << /CFM /AESV2 >> >>.
         */
        resolveCryptMethod(filterName) {
            if (!filterName) {
                const info = this.getEncryptionInfo();
                // V4 defaults StmF/StrF to Identity when omitted
                if (info.V >= 5) return '/AESV3';
                if (info.V === 4) return '/None';
                return '/V2';
            }

            const name = (typeof filterName === 'string')
                ? (filterName.startsWith('/') ? filterName : '/' + filterName)
                : null;
            if (!name) return '/V2';

            if (name === '/Identity' || name === '/None') return '/None';
            if (name === '/AESV2' || name === '/AESV3' || name === '/V2' || name === '/AESV4') {
                return name;
            }

            // Named filter in /CF dictionary (e.g. /StdCF)
            const cf = this.encryptDict['/CF'];
            if (cf && typeof cf === 'object') {
                const filterDict = cf[name] || cf[name.replace(/^\//, '')];
                if (filterDict && typeof filterDict === 'object') {
                    const cfm = filterDict['/CFM'];
                    if (cfm === '/AESV2' || cfm === '/AESV3' || cfm === '/V2' ||
                        cfm === '/AESV4' || cfm === '/None' || cfm === '/Identity') {
                        return cfm === '/Identity' ? '/None' : cfm;
                    }
                }
            }

            // Heuristic: V4 security handler almost always means AESV2 for StdCF
            const info = this.getEncryptionInfo();
            if (info.V >= 5) return '/AESV3';
            if (info.V === 4) return '/AESV2';
            return '/V2';
        }

        decryptStream(streamData, objNum, genNum) {
            if (!this.encryptionKey) {
                this.computeEncryptionKey();
            }
            
            const info = this.getEncryptionInfo();
            const method = this.resolveCryptMethod(this.encryptDict['/StmF']);
            
            console.log('PDFDecrypt: decryptStream obj', objNum, 'method=', method,
                'StmF=', this.encryptDict['/StmF'], 'len=', streamData.length);

            if (method === '/None' || method === '/Identity') {
                return streamData;
            }
            if (method === '/AESV2' || method === '/AESV3' || method === '/AESV4' || info.V >= 5) {
                if (info.V >= 5 || method === '/AESV3') {
                    return this.decryptAESV3(streamData);
                }
                return this.decryptAES(streamData, objNum, genNum);
            }
            
            return this.decryptRC4(streamData, objNum, genNum);
        }

        decryptString(stringData, objNum, genNum) {
            if (!this.encryptionKey) {
                this.computeEncryptionKey();
            }
            
            const info = this.getEncryptionInfo();
            const method = this.resolveCryptMethod(this.encryptDict['/StrF']);

            if (method === '/None' || method === '/Identity') {
                return stringData;
            }
            if (method === '/AESV2' || method === '/AESV3' || method === '/AESV4' || info.V >= 5) {
                if (info.V >= 5 || method === '/AESV3') {
                    return this.decryptAESV3(stringData);
                }
                return this.decryptAES(stringData, objNum, genNum);
            }
            
            return this.decryptRC4(stringData, objNum, genNum);
        }

        /**
         * True if this stream dictionary says use Identity crypt (do not decrypt).
         */
        streamUsesIdentityCrypt(dictStr) {
            if (!dictStr) return false;
            // /Filter /Crypt or /Filter [/Crypt ...] with /Name /Identity
            if (/\/Name\s*\/Identity/.test(dictStr) && /\/Crypt/.test(dictStr)) {
                return true;
            }
            // EncryptMetadata false → Metadata streams are not encrypted
            if (this.encryptDict['/EncryptMetadata'] === false &&
                /\/Type\s*\/Metadata/.test(dictStr)) {
                return true;
            }
            return false;
        }

        decryptRC4(data, objNum, genNum) {
            // Create object key
            const objKey = Utils.concatBytes(
                this.encryptionKey,
                new Uint8Array([objNum & 0xFF, (objNum >> 8) & 0xFF, (objNum >> 16) & 0xFF]),
                new Uint8Array([genNum & 0xFF, (genNum >> 8) & 0xFF])
            );
            
            let keyLength = Math.min(objKey.length, 16);
            const md5Hash = MD5.hash(objKey);
            const decryptKey = md5Hash.slice(0, keyLength);
            
            return RC4.crypt(decryptKey, data);
        }

        decryptAES(data, objNum, genNum) {
            if (!data || data.length < 32) {
                console.warn('PDFDecrypt: AES stream too short for obj', objNum, 'len=', data ? data.length : 0);
                return data;
            }
            // Create object key
            const objKey = Utils.concatBytes(
                this.encryptionKey,
                new Uint8Array([objNum & 0xFF, (objNum >> 8) & 0xFF, (objNum >> 16) & 0xFF]),
                new Uint8Array([genNum & 0xFF, (genNum >> 8) & 0xFF]),
                Utils.stringToBytes('sAlT') // AES marker
            );
            
            const md5Hash = MD5.hash(objKey);
            const decryptKey = md5Hash.slice(0, 16);
            
            // IV is first 16 bytes
            const iv = data.slice(0, 16);
            const ciphertext = data.slice(16);
            
            return AES.decryptCBC(decryptKey, iv, ciphertext);
        }

        decryptAESV3(data) {
            if (!data || data.length < 32) {
                return data;
            }
            // AES-256: key is used directly
            const iv = data.slice(0, 16);
            const ciphertext = data.slice(16);
            
            return AES.decryptCBC(this.encryptionKey, iv, ciphertext);
        }
    }

    // ============================================
    // SECTION 9: PDF WRITER (Creates unencrypted PDF)
    // ============================================
    
    class PDFWriter {
        constructor() {
            this.objects = [];
            this.offsets = [];
        }

        addObject(content) {
            const num = this.objects.length + 1;
            this.objects.push(content);
            return num;
        }

        build() {
            const parts = [];
            parts.push('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
            
            // Write objects
            for (let i = 0; i < this.objects.length; i++) {
                this.offsets[i] = parts.join('').length;
                parts.push(`${i + 1} 0 obj\n`);
                parts.push(this.objects[i]);
                parts.push('\nendobj\n');
            }
            
            // Write xref
            const xrefOffset = parts.join('').length;
            parts.push('xref\n');
            parts.push(`0 ${this.objects.length + 1}\n`);
            parts.push('0000000000 65535 f \n');
            for (let i = 0; i < this.objects.length; i++) {
                parts.push(String(this.offsets[i]).padStart(10, '0') + ' 00000 n \n');
            }
            
            // Write trailer
            parts.push('trailer\n');
            parts.push(`<< /Size ${this.objects.length + 1} /Root 1 0 R >>\n`);
            parts.push('startxref\n');
            parts.push(`${xrefOffset}\n`);
            parts.push('%%EOF');
            
            const str = parts.join('');
            return Utils.stringToBytes(str);
        }
    }

    // ============================================
    // SECTION 10: MAIN API
    // ============================================
    
    const PDFDecrypt = {
        /**
         * Extract ID array directly from raw PDF
         */
        extractIDArrayFromRaw: function(pdfData) {
            const pdfStr = Utils.bytesToString(pdfData);
            
            // Look for /ID array in trailer or elsewhere
            const idMatch = pdfStr.match(/\/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\]/);
            if (idMatch) {
                console.log('PDFDecrypt: Extracted ID array from raw PDF');
                return [
                    Utils.hexToBytes(idMatch[1]),
                    Utils.hexToBytes(idMatch[2])
                ];
            }
            
            // Try alternative format with parentheses
            const idMatch2 = pdfStr.match(/\/ID\s*\[\s*\(([^)]*)\)\s*\(([^)]*)\)\s*\]/);
            if (idMatch2) {
                console.log('PDFDecrypt: Extracted ID array (literal string format) from raw PDF');
                return [
                    Utils.stringToBytes(idMatch2[1]),
                    Utils.stringToBytes(idMatch2[2])
                ];
            }
            
            console.log('PDFDecrypt: Could not find ID array in raw PDF');
            return null;
        },
        
        /**
         * Extract encryption dictionary parameters directly from raw PDF
         */
        extractEncryptDictFromRaw: function(pdfData) {
            const pdfStr = Utils.bytesToString(pdfData);
            
            console.log('PDFDecrypt: Attempting raw encryption dict extraction...');
            
            // Find the encryption dictionary by looking for /Filter /Standard
            // Prefer the last match (most recent incremental update / trailer area)
            let filterIdx = -1;
            const filterRe = /\/Filter\s*\/Standard/g;
            let m;
            while ((m = filterRe.exec(pdfStr)) !== null) {
                filterIdx = m.index;
            }
            if (filterIdx === -1) {
                console.log('PDFDecrypt: Could not find /Filter /Standard in raw PDF');
                return null;
            }
            
            // Find the start of the dictionary containing this filter
            let dictStart = filterIdx;
            let depth = 0;
            while (dictStart > 0) {
                if (pdfStr.substr(dictStart, 2) === '<<') {
                    if (depth === 0) break;
                    depth--;
                } else if (pdfStr.substr(dictStart, 2) === '>>') {
                    depth++;
                }
                dictStart--;
            }
            
            // Find the object number by searching backwards for "X Y obj"
            const beforeDict = pdfStr.substring(Math.max(0, dictStart - 100), dictStart);
            const objMatch = beforeDict.match(/(\d+)\s+(\d+)\s+obj\s*$/);
            if (objMatch) {
                console.log('PDFDecrypt: Found encrypt dict object number:', objMatch[1]);
            }
            
            // Find the end of the dictionary
            let dictEnd = dictStart + 2;
            depth = 1;
            while (dictEnd < pdfStr.length && depth > 0) {
                if (pdfStr.substr(dictEnd, 2) === '<<') {
                    depth++;
                    dictEnd += 2;
                } else if (pdfStr.substr(dictEnd, 2) === '>>') {
                    depth--;
                    dictEnd += 2;
                } else {
                    dictEnd++;
                }
            }
            
            const dictContent = pdfStr.substring(dictStart, dictEnd);
            console.log('PDFDecrypt: Found encryption dict (length ' + dictContent.length + ')');
            
            const encryptDict = {};
            
            // Extract /V (version)
            const vMatch = dictContent.match(/\/V\s+(\d+)/);
            if (vMatch) encryptDict['/V'] = parseInt(vMatch[1], 10);
            
            // Extract /R (revision)
            const rMatch = dictContent.match(/\/R\s+(\d+)/);
            if (rMatch) encryptDict['/R'] = parseInt(rMatch[1], 10);
            
            // Extract /P (permissions)
            const pMatch = dictContent.match(/\/P\s+(-?\d+)/);
            if (pMatch) encryptDict['/P'] = parseInt(pMatch[1], 10);
            
            // Extract /Length (key length — not stream length). Prefer value near /V|/R.
            const lenMatch = dictContent.match(/\/Length\s+(\d+)/);
            if (lenMatch) encryptDict['/Length'] = parseInt(lenMatch[1], 10);
            
            // Helper: parse PDF literal string `(...)` with escapes into bytes
            const parseLiteralStringAt = (str, openParenIdx) => {
                const result = [];
                let i = openParenIdx + 1;
                let depth = 1;
                while (i < str.length && depth > 0) {
                    const ch = str.charCodeAt(i++);
                    if (ch === 0x5C) { // backslash
                        if (i >= str.length) break;
                        const next = str.charCodeAt(i++);
                        if (next === 0x6E) result.push(0x0A);
                        else if (next === 0x72) result.push(0x0D);
                        else if (next === 0x74) result.push(0x09);
                        else if (next === 0x62) result.push(0x08);
                        else if (next === 0x66) result.push(0x0C);
                        else if (next >= 0x30 && next <= 0x37) {
                            let octal = next - 0x30;
                            for (let k = 0; k < 2 && i < str.length; k++) {
                                const d = str.charCodeAt(i);
                                if (d >= 0x30 && d <= 0x37) {
                                    octal = (octal << 3) | (d - 0x30);
                                    i++;
                                } else break;
                            }
                            result.push(octal & 0xFF);
                        } else {
                            result.push(next & 0xFF);
                        }
                    } else if (ch === 0x28) { // (
                        depth++;
                        result.push(ch);
                    } else if (ch === 0x29) { // )
                        depth--;
                        if (depth > 0) result.push(ch);
                    } else {
                        result.push(ch & 0xFF);
                    }
                }
                return new Uint8Array(result);
            };
            
            const extractByteString = (key) => {
                // Hex form: /O <...>
                const hexRe = new RegExp('\\/' + key + '\\s*<([0-9A-Fa-f]+)>');
                const hexMatch = dictContent.match(hexRe);
                if (hexMatch) {
                    return Utils.hexToBytes(hexMatch[1]);
                }
                // Literal form: /O (...)
                const litRe = new RegExp('\\/' + key + '\\s*\\(');
                const litMatch = dictContent.match(litRe);
                if (litMatch) {
                    return parseLiteralStringAt(dictContent, litMatch.index + litMatch[0].length - 1);
                }
                return null;
            };
            
            const oBytes = extractByteString('O');
            if (oBytes) encryptDict['/O'] = oBytes;
            
            const uBytes = extractByteString('U');
            if (uBytes) encryptDict['/U'] = uBytes;
            
            const oeBytes = extractByteString('OE');
            if (oeBytes) encryptDict['/OE'] = oeBytes;
            
            const ueBytes = extractByteString('UE');
            if (ueBytes) encryptDict['/UE'] = ueBytes;
            
            const permsBytes = extractByteString('Perms');
            if (permsBytes) encryptDict['/Perms'] = permsBytes;
            
            // Extract crypt filter info
            const stmfMatch = dictContent.match(/\/StmF\s*\/(\w+)/);
            if (stmfMatch) encryptDict['/StmF'] = '/' + stmfMatch[1];
            
            const strfMatch = dictContent.match(/\/StrF\s*\/(\w+)/);
            if (strfMatch) encryptDict['/StrF'] = '/' + strfMatch[1];
            
            encryptDict['/Filter'] = '/Standard';
            
            console.log('PDFDecrypt: Extracted encryption params - V:', encryptDict['/V'], 'R:', encryptDict['/R'],
                'O:', encryptDict['/O'] ? encryptDict['/O'].length : 0,
                'U:', encryptDict['/U'] ? encryptDict['/U'].length : 0);
            
            return encryptDict;
        },
        
        /**
         * Check if a PDF is encrypted
         */
        isEncrypted: function(pdfData) {
            try {
                if (!(pdfData instanceof Uint8Array)) {
                    pdfData = new Uint8Array(pdfData);
                }

                const parser = new PDFParser(pdfData);
                parser.parse();
                const decryptor = new PDFDecryptor(parser, '');
                const isEnc = decryptor.isEncrypted();
                
                // Double-check by looking for encryption markers in raw PDF.
                // IMPORTANT: search head + tail (not only first 50KB) so large
                // encrypted PDFs whose /Encrypt lives near startxref still match.
                if (!isEnc) {
                    if (Utils.hasEncryptionMarkers(pdfData)) {
                        console.log('PDFDecrypt: Found encryption markers in PDF (head/tail scan) - appears encrypted');
                        return true;
                    }
                }
                
                return isEnc;
            } catch (e) {
                console.error('PDFDecrypt: Error checking encryption:', e);
                // On error, check raw PDF for encryption markers (full head+tail)
                try {
                    if (Utils.hasEncryptionMarkers(pdfData)) {
                        console.log('PDFDecrypt: Found encryption markers in PDF despite parse error');
                        return true;
                    }
                } catch (e2) {
                    // Ignore
                }
                return false;
            }
        },

        /**
         * Get encryption information
         */
        getEncryptionInfo: function(pdfData) {
            try {
                const parser = new PDFParser(pdfData);
                parser.parse();
                const decryptor = new PDFDecryptor(parser, '');
                return decryptor.getEncryptionInfo();
            } catch (e) {
                console.error('PDFDecrypt: Error getting encryption info:', e);
                return null;
            }
        },

        /**
         * Verify password
         */
        verifyPassword: function(pdfData, password) {
            try {
                if (!(pdfData instanceof Uint8Array)) {
                    pdfData = new Uint8Array(pdfData);
                }

                const parser = new PDFParser(pdfData);
                parser.parse();
                let decryptor = new PDFDecryptor(parser, password);

                // If parser missed the encrypt dict (common on large XRef-stream PDFs),
                // recover it from raw bytes before treating the file as unencrypted.
                if (!decryptor.isEncrypted() && Utils.hasEncryptionMarkers(pdfData)) {
                    console.log('PDFDecrypt: verifyPassword — recovering encrypt dict from raw PDF');
                    parser.findEncryptDictDirect(Utils.bytesToString(pdfData));
                    decryptor = new PDFDecryptor(parser, password);
                    if (!decryptor.isEncrypted()) {
                        const encryptDict = this.extractEncryptDictFromRaw(pdfData);
                        if (encryptDict) {
                            parser.encryptDict = encryptDict;
                            if (!parser.idArray) {
                                parser.idArray = this.extractIDArrayFromRaw(pdfData);
                            }
                            decryptor = new PDFDecryptor(parser, password);
                        }
                    }
                }

                if (!decryptor.isEncrypted()) {
                    // Truly not encrypted
                    return true;
                }

                return decryptor.verifyPassword();
            } catch (e) {
                console.error('PDFDecrypt: Error verifying password:', e);
                return false;
            }
        },

        /**
         * Decrypt encrypted strings within a PDF object
         * @param {string} objStr - The object content as string
         * @param {number} objNum - Object number
         * @param {number} genNum - Generation number
         * @param {PDFDecryptor} decryptor - The decryptor instance
         * @returns {string} - Object with decrypted strings
         */
        decryptObjectStrings: function(objStr, objNum, genNum, decryptor) {
            // Decrypt literal strings (...)
            let result = objStr;
            
            // Find and decrypt literal strings
            const literalRegex = /\(([^)]*(?:\)[^)]*)*)\)/g;
            result = result.replace(literalRegex, (match) => {
                try {
                    // Parse the string content (handle escapes)
                    const content = match.slice(1, -1);
                    const bytes = [];
                    let i = 0;
                    while (i < content.length) {
                        if (content[i] === '\\') {
                            i++;
                            if (i >= content.length) break;
                            const next = content[i];
                            if (next === 'n') bytes.push(0x0A);
                            else if (next === 'r') bytes.push(0x0D);
                            else if (next === 't') bytes.push(0x09);
                            else if (next === 'b') bytes.push(0x08);
                            else if (next === 'f') bytes.push(0x0C);
                            else if (next >= '0' && next <= '7') {
                                let octal = next;
                                if (content[i+1] >= '0' && content[i+1] <= '7') {
                                    i++;
                                    octal += content[i];
                                    if (content[i+1] >= '0' && content[i+1] <= '7') {
                                        i++;
                                        octal += content[i];
                                    }
                                }
                                bytes.push(parseInt(octal, 8));
                            } else {
                                bytes.push(next.charCodeAt(0));
                            }
                        } else {
                            bytes.push(content.charCodeAt(i));
                        }
                        i++;
                    }
                    
                    if (bytes.length === 0) return match;
                    
                    const encrypted = new Uint8Array(bytes);
                    const decrypted = decryptor.decryptString(encrypted, objNum, genNum);
                    
                    // Convert back to PDF string format
                    let str = '(';
                    for (let j = 0; j < decrypted.length; j++) {
                        const c = decrypted[j];
                        if (c === 0x0A) str += '\\n';
                        else if (c === 0x0D) str += '\\r';
                        else if (c === 0x09) str += '\\t';
                        else if (c === 0x08) str += '\\b';
                        else if (c === 0x0C) str += '\\f';
                        else if (c === 0x28) str += '\\(';
                        else if (c === 0x29) str += '\\)';
                        else if (c === 0x5C) str += '\\\\';
                        else if (c >= 32 && c < 127) str += String.fromCharCode(c);
                        else str += '\\' + c.toString(8).padStart(3, '0');
                    }
                    str += ')';
                    return str;
                } catch (e) {
                    // If decryption fails, return original
                    return match;
                }
            });
            
            // Find and decrypt hex strings <...>
            // But skip dictionary markers << and >>
            const hexRegex = /<([0-9A-Fa-f\s]+)>/g;
            result = result.replace(hexRegex, (match, hexContent) => {
                try {
                    const hex = hexContent.replace(/\s/g, '');
                    if (hex.length === 0) return match;
                    
                    const bytes = Utils.hexToBytes(hex.length % 2 ? hex + '0' : hex);
                    const decrypted = decryptor.decryptString(bytes, objNum, genNum);
                    
                    return '<' + Utils.bytesToHex(decrypted) + '>';
                } catch (e) {
                    return match;
                }
            });
            
            return result;
        },

        /**
         * Decrypt PDF and return new unencrypted PDF
         * PROPER APPROACH: Rebuild entire PDF with decrypted content
         */
        decrypt: function(pdfData, password) {
            console.log('PDFDecrypt: Starting decryption...');
            
            if (!(pdfData instanceof Uint8Array)) {
                pdfData = new Uint8Array(pdfData);
            }
            
            // Parse the PDF
            const parser = new PDFParser(pdfData);
            parser.parse();
            
            // Check encryption - also do a raw check to be sure
            let decryptor = new PDFDecryptor(parser, password);
            let isEnc = decryptor.isEncrypted();
            
            console.log('PDFDecrypt: Initial encryption check:', isEnc);
            
            // Double-check by looking for encryption markers in raw PDF
            // For large PDFs, encryption dict is usually near the end — scan head+tail
            if (!isEnc) {
                const hasEncryptMarker = Utils.hasEncryptionMarkers(pdfData);
                
                console.log('PDFDecrypt: Raw PDF has encryption markers:', hasEncryptMarker);
                
                if (hasEncryptMarker) {
                    console.log('PDFDecrypt: Found encryption markers in raw PDF, trying to parse encrypt dict...');
                    // Try to find and parse the encrypt dict directly (use full file)
                    const pdfStr = Utils.bytesToString(pdfData);
                    parser.findEncryptDictDirect(pdfStr);
                    // Re-create decryptor with updated parser
                    decryptor = new PDFDecryptor(parser, password);
                    isEnc = decryptor.isEncrypted();
                    console.log('PDFDecrypt: After findEncryptDictDirect, isEncrypted:', isEnc);
                    
                    if (!isEnc) {
                        console.log('PDFDecrypt: Still cannot find encryption dict, attempting raw extraction...');
                        // Try to extract encryption parameters directly from PDF
                        const encryptDict = this.extractEncryptDictFromRaw(pdfData);
                        console.log('PDFDecrypt: Raw extraction result:', encryptDict ? 'found' : 'not found');
                        if (encryptDict) {
                            console.log('PDFDecrypt: V=' + encryptDict['/V'] + ', R=' + encryptDict['/R'] + 
                                       ', O len=' + (encryptDict['/O'] ? encryptDict['/O'].length : 0) +
                                       ', U len=' + (encryptDict['/U'] ? encryptDict['/U'].length : 0));
                            parser.encryptDict = encryptDict;
                            // Also extract ID array if not already found
                            if (!parser.idArray) {
                                parser.idArray = this.extractIDArrayFromRaw(pdfData);
                                console.log('PDFDecrypt: ID array extracted:', parser.idArray ? 'yes' : 'no');
                            }
                            decryptor = new PDFDecryptor(parser, password);
                            isEnc = decryptor.isEncrypted();
                            console.log('PDFDecrypt: After raw extraction, isEncrypted:', isEnc);
                        }
                    }
                }
            }
            
            if (!isEnc) {
                console.log('PDFDecrypt: PDF is not encrypted, returning as-is');
                return pdfData;
            }
            
            console.log('PDFDecrypt: PDF is encrypted, verifying password...');
            
            // Verify password
            if (!decryptor.verifyPassword()) {
                throw new Error('Invalid password');
            }
            
            console.log('PDFDecrypt: Password verified, rebuilding PDF...');

            // Re-parse XRef with decryption — required for encrypted XRef streams
            try {
                parser.reparseXRefWithDecryptor(decryptor);
            } catch (e) {
                console.warn('PDFDecrypt: XRef reparse warning:', e.message);
            }


            // Log crypt methods so AES-via-StdCF misdetects are obvious in console
            try {
                console.log('PDFDecrypt: StmF=', decryptor.encryptDict['/StmF'],
                    '→', decryptor.resolveCryptMethod(decryptor.encryptDict['/StmF']),
                    'StrF=', decryptor.encryptDict['/StrF'],
                    '→', decryptor.resolveCryptMethod(decryptor.encryptDict['/StrF']));
            } catch (e) {}
            
            // STRATEGY: Rebuild PDF with decrypted content using BINARY chunks
            // (string concatenation corrupts / is unsafe for large stream payloads)
            
            const chunks = [];
            let outputLength = 0;
            const appendBytes = (bytes) => {
                if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
                chunks.push(bytes);
                outputLength += bytes.length;
            };
            const appendStr = (str) => appendBytes(Utils.stringToBytes(str));
            
            appendStr('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');
            
            const objectOffsets = [];
            
            // Get encrypt dict ref to skip it
            const encryptRef = parser.trailer && parser.trailer['/Encrypt'];
            const encryptObjNum = (encryptRef && encryptRef.ref) ? encryptRef.num
                : (encryptRef && typeof encryptRef.num === 'number' ? encryptRef.num : -1);
            
            // Collect object streams to skip (we'll extract their contents instead)
            const objectStreamNums = new Set();
            for (const [key, info] of parser.objectStreams.entries()) {
                objectStreamNums.add(info.streamObjNum);
            }
            
            const removeEncryptionFromDict = (dictStr) => {
                dictStr = dictStr.replace(/\/Encrypt\s+\d+\s+\d+\s+R\s*/g, '');
                dictStr = dictStr.replace(/\/Encrypt\s*<<[^>]*(?:<<[^>]*>>[^>]*)*>>\s*/g, '');
                dictStr = dictStr.replace(/\/EncryptMetadata\s+(true|false)\s*/gi, '');
                dictStr = dictStr.replace(/\/Perms\s+\d+\s+\d+\s+R\s*/g, '');
                dictStr = dictStr.replace(/\/Perms\s*<<[^>]*>>\s*/g, '');
                dictStr = dictStr.replace(/\/CF\s*<<[^>]*(?:<<[^>]*>>[^>]*)*>>\s*/g, '');
                dictStr = dictStr.replace(/\/StmF\s*\/\w+\s*/g, '');
                dictStr = dictStr.replace(/\/StrF\s*\/\w+\s*/g, '');
                dictStr = dictStr.replace(/\/EFF\s*\/\w+\s*/g, '');
                dictStr = dictStr.replace(/\/AuthEvent\s*\/\w+\s*/g, '');
                dictStr = dictStr.replace(/\/Recipients\s*\[[^\]]*\]\s*/g, '');
                // Strip /Crypt from Filter arrays (no longer encrypted)
                dictStr = dictStr.replace(/\/Filter\s*\[\s*\/Crypt\s*/g, '/Filter [');
                dictStr = dictStr.replace(/\/Filter\s*\/Crypt\b\s*/g, '');
                dictStr = dictStr.replace(/\/DecodeParms\s*\[\s*<<[^>]*\/Type\s*\/CryptFilterDecodeParms[^>]*>>\s*/g, '/DecodeParms [');
                dictStr = dictStr.replace(/\/DecodeParms\s*<<[^>]*\/Type\s*\/CryptFilterDecodeParms[^>]*>>\s*/g, '');
                dictStr = dictStr.replace(/\s{2,}/g, ' ');
                return dictStr;
            };
            
            const isXRefStream = (objStr) => objStr.includes('/Type') && objStr.includes('/XRef');
            const isEncryptionDictObject = (objStr) => {
                return (objStr.includes('/Filter') && objStr.includes('/Standard')) ||
                       (objStr.includes('/V ') && objStr.includes('/R ') &&
                        (objStr.includes('/O ') || objStr.includes('/U ')));
            };

            /**
             * Locate stream payload using /Length (avoids false "endstream" hits inside binary).
             */
            const extractStreamPayload = (objBytes, objStr) => {
                const streamKeywordPos = objStr.indexOf('stream');
                if (streamKeywordPos === -1) return null;

                let streamDataStart = streamKeywordPos + 6;
                if (objBytes[streamDataStart] === 0x0D) streamDataStart++;
                if (objBytes[streamDataStart] === 0x0A) streamDataStart++;

                let length = null;
                const lenMatch = objStr.substring(0, streamKeywordPos).match(/\/Length\s+(\d+)(?!\s+\d+\s+R)/);
                if (lenMatch) {
                    length = parseInt(lenMatch[1], 10);
                }

                let streamDataEnd;
                if (typeof length === 'number' && length >= 0 &&
                    streamDataStart + length <= objBytes.length) {
                    streamDataEnd = streamDataStart + length;
                } else {
                    // Fallback: search for endstream as bytes (not via latin1 indexOf on whole obj)
                    const endMarker = Utils.stringToBytes('endstream');
                    streamDataEnd = -1;
                    outer: for (let i = streamDataStart; i <= objBytes.length - endMarker.length; i++) {
                        for (let j = 0; j < endMarker.length; j++) {
                            if (objBytes[i + j] !== endMarker[j]) continue outer;
                        }
                        streamDataEnd = i;
                        break;
                    }
                    if (streamDataEnd === -1) return null;
                    while (streamDataEnd > streamDataStart &&
                           (objBytes[streamDataEnd - 1] === 0x0A || objBytes[streamDataEnd - 1] === 0x0D)) {
                        streamDataEnd--;
                    }
                }

                return {
                    streamKeywordPos,
                    dictPart: objStr.substring(0, streamKeywordPos),
                    encryptedStream: objBytes.slice(streamDataStart, streamDataEnd)
                };
            };

            /**
             * Find endobj boundary without scanning through stream binary via string search.
             */
            const findObjectEnd = (startOffset) => {
                // Quick ASCII scan for 'endobj' at byte level
                const marker = Utils.stringToBytes('endobj');
                for (let i = startOffset; i <= pdfData.length - marker.length; i++) {
                    let ok = true;
                    for (let j = 0; j < marker.length; j++) {
                        if (pdfData[i + j] !== marker[j]) { ok = false; break; }
                    }
                    if (ok) {
                        // Prefer matches that look like token boundaries
                        const before = i > 0 ? pdfData[i - 1] : 0x0A;
                        if (before === 0x0A || before === 0x0D || before === 0x20) {
                            return i + marker.length;
                        }
                    }
                }
                return pdfData.length;
            };
            
            const sortedXref = Array.from(parser.xref.entries())
                .map(([key, value]) => {
                    const [num, gen] = key.split(' ').map(Number);
                    return { num, gen, offset: value.offset };
                })
                .sort((a, b) => a.num - b.num);
            
            console.log('PDFDecrypt: Processing', sortedXref.length, 'direct objects');
            console.log('PDFDecrypt: Processing', parser.objectStreams.size, 'objects from object streams');
            
            const processedObjects = new Set();
            let streamDecryptCount = 0;
            let streamSkipCount = 0;
            
            for (const entry of sortedXref) {
                const { num, gen, offset } = entry;
                
                if (num === encryptObjNum) {
                    console.log('PDFDecrypt: Skipping encrypt object', num);
                    continue;
                }
                
                if (objectStreamNums.has(num)) {
                    continue;
                }
                
                if (typeof offset !== 'number' || offset < 0 || offset >= pdfData.length) {
                    console.warn('PDFDecrypt: Bad offset for object', num, offset);
                    continue;
                }

                const objEndPos = findObjectEnd(offset);
                const objBytes = pdfData.slice(offset, objEndPos);
                // Only decode the dictionary portion as string when needed — for type checks use a head sample
                const headSample = Utils.bytesToString(objBytes.slice(0, Math.min(objBytes.length, 2048)));
                const objStr = Utils.bytesToString(objBytes);
                
                if (isXRefStream(headSample)) {
                    console.log('PDFDecrypt: Skipping XRef stream object', num);
                    continue;
                }
                
                if (isEncryptionDictObject(headSample)) {
                    console.log('PDFDecrypt: Skipping encryption dict object', num);
                    continue;
                }
                
                processedObjects.add(num);
                objectOffsets.push({ num, gen, offset: outputLength });

                const streamInfo = extractStreamPayload(objBytes, objStr);
                
                if (streamInfo) {
                    const { dictPart, encryptedStream } = streamInfo;
                    let decryptedStream = encryptedStream;

                    const skipCrypt = decryptor.streamUsesIdentityCrypt(dictPart);
                    if (skipCrypt) {
                        streamSkipCount++;
                    } else {
                        try {
                            decryptedStream = decryptor.decryptStream(encryptedStream, num, gen);
                            streamDecryptCount++;
                        } catch (e) {
                            console.warn('PDFDecrypt: Failed to decrypt stream', num, e.message);
                            decryptedStream = encryptedStream;
                        }
                    }
                    
                    let newDict = removeEncryptionFromDict(dictPart);
                    newDict = newDict.replace(/\/Length\s+\d+(\s+\d+\s+R)?/g, '/Length ' + decryptedStream.length);
                    
                    appendStr(newDict);
                    appendStr('stream\n');
                    appendBytes(decryptedStream);
                    appendStr('\nendstream\nendobj\n');
                } else {
                    let cleaned = removeEncryptionFromDict(objStr);
                    // Avoid decrypting strings inside binary-looking content without stream keyword
                    cleaned = this.decryptObjectStrings(cleaned, num, gen, decryptor);
                    if (!/\bendobj\s*$/.test(cleaned)) {
                        cleaned = cleaned.replace(/\s*$/, '') + '\nendobj\n';
                    } else if (!cleaned.endsWith('\n')) {
                        cleaned += '\n';
                    }
                    appendStr(cleaned);
                }
            }
            
            // Objects from object streams
            const objectsByStream = new Map();
            for (const [key, info] of parser.objectStreams.entries()) {
                const [num] = key.split(' ').map(Number);
                if (processedObjects.has(num) || num === encryptObjNum) continue;
                if (!objectsByStream.has(info.streamObjNum)) {
                    objectsByStream.set(info.streamObjNum, []);
                }
                objectsByStream.get(info.streamObjNum).push({ num, key, info });
            }
            
            const isEncryptionDict = (content) => {
                return content.includes('/Filter') &&
                       (content.includes('/Standard') || content.includes('/Adobe.PubSec')) &&
                       (content.includes('/V ') || content.includes('/R ') || content.includes('/O ') || content.includes('/U '));
            };
            
            for (const [streamObjNum, objects] of objectsByStream.entries()) {
                console.log('PDFDecrypt: Extracting objects from object stream', streamObjNum);
                
                let extractedObjects = [];
                try {
                    extractedObjects = parser.extractAllFromObjectStream(streamObjNum, decryptor) || [];
                } catch (e) {
                    console.warn('PDFDecrypt: Failed extracting object stream', streamObjNum, e.message);
                }
                
                for (const extracted of extractedObjects) {
                    if (processedObjects.has(extracted.objNum) || extracted.objNum === encryptObjNum) {
                        continue;
                    }
                    
                    let objContent = Utils.bytesToString(extracted.bytes).trim();
                    
                    if (isEncryptionDict(objContent)) continue;
                    if (objContent.includes('/Type') && objContent.includes('/XRef')) continue;
                    
                    processedObjects.add(extracted.objNum);
                    objContent = removeEncryptionFromDict(objContent);
                    objContent = this.decryptObjectStrings(objContent, extracted.objNum, 0, decryptor);
                    
                    objectOffsets.push({ num: extracted.objNum, gen: 0, offset: outputLength });
                    appendStr(`${extracted.objNum} 0 obj\n`);
                    appendStr(objContent + '\n');
                    appendStr('endobj\n');
                }
            }
            
            console.log('PDFDecrypt: Decrypted streams=', streamDecryptCount,
                'identity/skipped=', streamSkipCount,
                'objects written=', objectOffsets.length);
            
            // xref table
            const xrefOffset = outputLength;
            objectOffsets.sort((a, b) => a.num - b.num);
            const maxObjNum = objectOffsets.length > 0 ?
                Math.max(...objectOffsets.map(e => e.num)) : 0;
            
            const offsetMap = new Map();
            for (const entry of objectOffsets) {
                offsetMap.set(entry.num, entry.offset);
            }
            
            appendStr('xref\n');
            appendStr('0 ' + (maxObjNum + 1) + '\n');
            appendStr('0000000000 65535 f \n');
            
            for (let i = 1; i <= maxObjNum; i++) {
                if (offsetMap.has(i)) {
                    appendStr(String(offsetMap.get(i)).padStart(10, '0') + ' 00000 n \n');
                } else {
                    appendStr('0000000000 65535 f \n');
                }
            }
            
            appendStr('trailer\n<<\n');
            appendStr('/Size ' + (maxObjNum + 1) + '\n');
            
            if (parser.trailer && parser.trailer['/Root']) {
                const root = parser.trailer['/Root'];
                if (root.ref || (typeof root.num === 'number')) {
                    appendStr('/Root ' + root.num + ' ' + (root.gen || 0) + ' R\n');
                }
            }
            
            if (parser.trailer && parser.trailer['/Info']) {
                const infoRef = parser.trailer['/Info'];
                if (infoRef.ref || (typeof infoRef.num === 'number')) {
                    appendStr('/Info ' + infoRef.num + ' ' + (infoRef.gen || 0) + ' R\n');
                }
            }
            
            const idArr = parser.getIDArray && parser.getIDArray();
            if (idArr && idArr.length) {
                appendStr('/ID [');
                for (const idPart of idArr) {
                    appendStr('<' + Utils.bytesToHex(idPart) + '>');
                }
                appendStr(']\n');
            }
            
            appendStr('>>\n');
            appendStr('startxref\n');
            appendStr(xrefOffset + '\n');
            appendStr('%%EOF\n');
            
            const result = Utils.concatBytes.apply(null, chunks);
            console.log('PDFDecrypt: Decryption complete, output size:', result.length);

            // Sanity: output must still look like a PDF
            const outHead = Utils.bytesToString(result.slice(0, 8));
            if (!outHead.startsWith('%PDF')) {
                throw new Error('Decryption produced invalid PDF header');
            }

            return result;
        },

        decryptAndRebuild: async function(pdfData, password) {
            console.log('PDFDecrypt: Starting decrypt and rebuild...');
            
            if (!(pdfData instanceof Uint8Array)) {
                pdfData = new Uint8Array(pdfData);
            }
            
            const parser = new PDFParser(pdfData);
            parser.parse();
            
            const decryptor = new PDFDecryptor(parser, password);
            
            if (!decryptor.isEncrypted()) {
                console.log('PDFDecrypt: PDF is not encrypted');
                return pdfData;
            }
            
            if (!decryptor.verifyPassword()) {
                throw new Error('Invalid password');
            }
            
            // Get root catalog
            const rootRef = parser.trailer['/Root'];
            const catalog = parser.getObject(rootRef.num, rootRef.gen);
            
            // Get pages
            const pagesRef = catalog['/Pages'];
            const pages = parser.getObject(pagesRef.num, pagesRef.gen);
            
            console.log('PDFDecrypt: Found', pages['/Count'], 'pages');
            
            // Build new PDF with decrypted content
            const writer = new PDFWriter();
            
            // This is a simplified rebuild - for complex PDFs, you may need more sophisticated handling
            // For now, return the byte-level decrypted version
            return this.decrypt(pdfData, password);
        },

        // Expose utilities for advanced usage
        Utils: Utils,
        MD5: MD5,
        SHA256: SHA256,
        RC4: RC4,
        AES: AES,
        Inflate: Inflate,
        PDFParser: PDFParser,
        PDFDecryptor: PDFDecryptor,
        PDFWriter: PDFWriter
    };

    // Export to global
    global.PDFDecrypt = PDFDecrypt;

})(typeof window !== 'undefined' ? window : this);
