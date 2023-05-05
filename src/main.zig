const std = @import("std");
const aes = std.crypto.core.aes;
const mem = std.mem;
const debug = std.debug;

/// CBC mode with PKCS#7 padding.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// If you need authenticated encryption, use anything from `std.crypto.aead` instead.
/// If you really need to use CBC mode, make sure to use a MAC to authenticate the ciphertext.
pub fn CBC(comptime BlockCipher: anytype) type {
    const EncryptCtx = aes.AesEncryptCtx(BlockCipher);
    const DecryptCtx = aes.AesDecryptCtx(BlockCipher);

    return struct {
        const Self = @This();

        enc_ctx: EncryptCtx,
        dec_ctx: DecryptCtx,

        /// Initialize the CBC context with the given key.
        pub fn init(key: [BlockCipher.key_bits / 8]u8) Self {
            const enc_ctx = BlockCipher.initEnc(key);
            const dec_ctx = DecryptCtx.initFromEnc(enc_ctx);

            return Self{ .enc_ctx = enc_ctx, .dec_ctx = dec_ctx };
        }

        /// Return the length of the ciphertext given the length of the plaintext.
        pub fn paddedLength(length: usize) usize {
            return (std.math.divCeil(usize, length + 1, EncryptCtx.block_length) catch unreachable) * EncryptCtx.block_length;
        }

        /// Encrypt the given plaintext for the given IV.
        /// The destination buffer must be large enough to hold the padded plaintext.
        /// Use the `paddedLength()` function to compute the ciphertext size.
        /// IV must be secret and unpredictable.
        pub fn encrypt(self: Self, dst: []u8, src: []const u8, iv: [EncryptCtx.block_length]u8) void {
            const block_length = EncryptCtx.block_length;
            const padded_length = paddedLength(src.len);
            debug.assert(dst.len == padded_length); // destination buffer must hold the padded plaintext
            var cv = iv;
            var i: usize = 0;
            while (i + block_length <= src.len) : (i += block_length) {
                const in = src[i..][0..block_length];
                var j: usize = 0;
                while (j < block_length) : (j += 1) cv[j] ^= in[j];
                self.enc_ctx.encrypt(&cv, &cv);
                mem.copyForwards(u8, dst[i..], &cv);
            }
            // Last block
            {
                var in = [_]u8{0} ** block_length;
                var padding_length = @intCast(u8, padded_length - src.len);
                @memset(in[padding_length..], padding_length);
                mem.copyForwards(u8, in[0..], src[i..]);
                var j: usize = 0;
                while (j < block_length) : (j += 1) cv[j] ^= in[j];
                self.enc_ctx.encrypt(&cv, &cv);
                mem.copyForwards(u8, dst[i..], cv[0 .. dst.len - i]);
            }
        }

        /// Decrypt the given ciphertext for the given IV.
        /// The destination buffer must be large enough to hold the plaintext.
        /// IV must be secret, unpredictable and match the one used for encryption.
        pub fn decrypt(self: Self, dst: []u8, src: []const u8, iv: [DecryptCtx.block_length]u8) !void {
            const block_length = DecryptCtx.block_length;
            const padded_length = paddedLength(dst.len);
            if (src.len != padded_length) {
                return error.EncodingError;
            }
            debug.assert(src.len % block_length == 0);
            var i: usize = 0;
            var cv = &iv;
            // Decryption could be parallelized
            while (i + block_length <= dst.len) : (i += block_length) {
                const in = src[i..][0..block_length];
                const out = dst[i..][0..block_length];
                self.dec_ctx.decrypt(out, in);
                var j: usize = 0;
                while (j < block_length) : (j += 1) out[j] ^= cv[j];
                cv = in;
            }
            // Last block - We intentionally don't check the padding to mitigate timing attacks
            if (i < dst.len) {
                const in = src[i..][0..block_length];
                var out = [_]u8{0} ** block_length;
                self.dec_ctx.decrypt(&out, in);
                var j: usize = 0;
                while (j < block_length) : (j += 1) out[j] ^= cv[j];
                mem.copyForwards(u8, dst[i..], out[0 .. dst.len - i]);
            }
        }
    };
}

test "CBC mode" {
    const M = CBC(aes.Aes128);
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const src_ = "This is a test of AES-CBC";

    const z = M.init(key);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    comptime var len = 0;
    inline while (len <= src_.len) : (len += 1) {
        const src = src_[0..len];
        var dst = [_]u8{0} ** M.paddedLength(src.len);
        z.encrypt(&dst, src, iv);
        h.update(&dst);

        var decrypted = [_]u8{0} ** src.len;
        try z.decrypt(&decrypted, &dst, iv);

        try std.testing.expectEqualSlices(u8, src, &decrypted);
    }
    var res: [32]u8 = undefined;
    h.final(&res);
    const expected = [_]u8{ 94, 191, 122, 226, 45, 255, 237, 166, 158, 166, 49, 9, 236, 29, 2, 213, 88, 54, 90, 217, 117, 201, 62, 44, 8, 162, 243, 157, 91, 70, 246, 35 };
    try std.testing.expectEqualSlices(u8, &expected, &res);
}
