const std = @import("std");
const aes = std.crypto.core.aes;
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;

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
            return (std.math.divCeil(usize, length, EncryptCtx.block_length) catch unreachable) * EncryptCtx.block_length;
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
                @memcpy(dst[i .. i + block_length], &cv);
            }
            // Last block
            {
                var in = [_]u8{0} ** block_length;
                var padding_length = @intCast(u8, padded_length - src.len);
                @memset(in[padding_length..], padding_length);
                @memcpy(in[0 .. src.len - i], src[i..]);
                var j: usize = 0;
                while (j < block_length) : (j += 1) cv[j] ^= in[j];
                self.enc_ctx.encrypt(&cv, &cv);
                @memcpy(dst[i..], cv[0 .. dst.len - i]);
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
            var nextCV = &iv;
            // Decryption could be parallelized
            while (i + block_length <= dst.len) : (i += block_length) {
                const in = src[i..][0..block_length];
                const out = dst[i..][0..block_length];
                @memcpy(nextCV, in);
                self.dec_ctx.decrypt(out, in);
                var j: usize = 0;
                while (j < block_length) : (j += 1) out[j] ^= cv[j];
                @memcpy(cv, nextCV);
            }
            // Last block - We intentionally don't check the padding to mitigate timing attacks
            if (i < dst.len) {
                const in = src[i..][0..block_length];
                var out = [_]u8{0} ** block_length;
                self.dec_ctx.decrypt(&out, in);
                var j: usize = 0;
                while (j < block_length) : (j += 1) out[j] ^= cv[j];
                @memcpy(dst[i..], out[0 .. dst.len - i]);
            }
        }
    };
}

test "CBC mode" {
    const M = CBC(aes.Aes128);
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const src_ = "This is a test of AES-CBC that goes on longer than a couple blocks. It is a somewhat long test case to type out!";
    try std.testing.expect(src_.len % 16 == 0); // sanity check that the input aligns to block boundary

    const z = M.init(key);

    comptime var len = 0;
    inline while (len < src_.len) : (len += 1) {
        const src = src_[0..len];
        var dst = [_]u8{0} ** M.paddedLength(src.len);
        z.encrypt(&dst, src, iv);

        var decrypted = [_]u8{0} ** src.len;
        try z.decrypt(&decrypted, &dst, iv);

        try std.testing.expectEqualSlices(u8, src, &decrypted);
    }
}

test "encrypt and decrypt on block boundary" {
    const M = CBC(aes.Aes256);
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c } ** 2;
    const z = M.init(key);
    const iv = [_]u8{ 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

    //
    // Test various regions around the boundaries of a block
    //

    {
        const val = M.paddedLength(0);
        try std.testing.expectEqual(@as(usize, 0), val);
    }
    {
        const val = M.paddedLength(1);
        try std.testing.expectEqual(@as(usize, 16), val);
    }

    {
        const val = M.paddedLength(15);
        try std.testing.expectEqual(@as(usize, 16), val);
    }

    {
        // don't round up
        const val = M.paddedLength(16);
        try std.testing.expectEqual(@as(usize, 16), val);
    }

    {
        const val = M.paddedLength(17);
        try std.testing.expectEqual(@as(usize, 32), val);
    }

    //
    // Encrypt and decrypt a message that aligns on the block boundary
    //

    {
        // one-block case
        var payload_ = "0123456789abcdef";
        var payload = try testing.allocator.alloc(u8, payload_.len);
        defer testing.allocator.free(payload);
        try std.testing.expectEqual(@as(usize, 16), payload.len); // sanity check
        mem.copyForwards(u8, payload, payload_);

        z.encrypt(payload, payload, iv);
        try z.decrypt(payload, payload, iv);

        var byte: u8 = 0;
        while (byte < payload_.len) : (byte += 1) {
            try std.testing.expectEqual(payload_[byte], payload[byte]);
        }
    }

    {
        // three-block case
        var payload_ = "0123456789abcdef0123456789abcdef0123456789abcdef";
        try std.testing.expectEqual(@as(usize, 48), payload_.len); // sanity check

        var payload = try testing.allocator.alloc(u8, payload_.len);
        defer testing.allocator.free(payload);
        mem.copyForwards(u8, payload, payload_);

        {
            // test the case where the memory ranges do not overlap
            var out = try testing.allocator.alloc(u8, payload.len);
            defer testing.allocator.free(out);

            var final = try testing.allocator.alloc(u8, payload.len);
            defer testing.allocator.free(final);

            z.encrypt(out, payload, iv);
            try z.decrypt(final, out, iv);

            try testing.expectEqualSlices(u8, payload_, payload);
        }

        {
            // test the case where the memory ranges DO overlap
            z.encrypt(payload, payload, iv);

            // ensure the value has changed
            var same = true;
            for (payload_, payload) |before, after| {
                if (before != after) {
                    same = false;
                    break;
                }
            }
            try testing.expect(!same);

            try z.decrypt(payload, payload, iv);

            // back to its original value
            try testing.expectEqualSlices(u8, payload_, payload);
        }
    }
}

test "encrypt and decrypt not on block boundary" {
    const M = CBC(aes.Aes256);
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c } ** 2;
    const z = M.init(key);
    const iv = [_]u8{ 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

    var payload_ = "0123456789abcdef0123456789abcdef0123456789abc";
    try std.testing.expectEqual(@as(usize, 45), payload_.len); // sanity check

    var payload = try testing.allocator.alloc(u8, payload_.len);
    defer testing.allocator.free(payload);
    mem.copyForwards(u8, payload, payload_);

    var out = try testing.allocator.alloc(u8, M.paddedLength(payload.len));
    defer testing.allocator.free(out);

    var final = try testing.allocator.alloc(u8, M.paddedLength(payload.len));
    defer testing.allocator.free(final);

    z.encrypt(out, payload, iv);
    try z.decrypt(final, out, iv);
    try testing.expectEqual(payload_.len, final.len - 3);
    try testing.expectEqualSlices(u8, payload_, final[0..payload.len]);
}
