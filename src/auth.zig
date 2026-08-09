const std = @import("std");
const lib = @import("lib.zig");
const Buffer = @import("buffer").Buffer;

const proto = lib.proto;
const Reader = lib.Reader;
const Stream = lib.Stream;

const Allocator = std.mem.Allocator;
const Io = std.Io;

const Opts = lib.Conn.AuthOpts;

// Weird return (but Zig has no error payloads, so..)
// null on success
// a []const on a PG error
//   - can be be passed to  proto.Error.parse(owned)
//   - is only valid until the next call to reader.read()
//     (we expect our caller to clone the value)
// a normal zig error on any other error
pub fn auth(io: Io, stream: *Stream, buf: *Buffer, reader: *Reader, opts: Opts) !?[]const u8 {
    try reader.startFlow(null, opts.timeout);

    // ignore errors on endFlow, because it's troublesome to handle, and only
    // something really bad (like OOM) can happen, and that'll surface again
    // as soon as the app tries to use the connection.
    defer reader.endFlow() catch {};

    {
        // write our startup message
        const startup_message = proto.StartupMessage{
            .username = opts.username,
            .application_name = opts.application_name,
            .database = opts.database orelse opts.username,
        };

        buf.resetRetainingCapacity();
        try startup_message.write(buf);
        try stream.writeAll(buf.string());
    }

    // read the server's response
    {
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.UnexpectedDBMessage,
        }

        switch (try proto.AuthenticationRequest.parse(msg.data)) {
            .ok => return null,
            .sasl => |sasl| if (try saslAuth(io, sasl, stream, buf, reader, opts)) |raw_pg_err| {
                return raw_pg_err;
            },
            .md5 => |salt| try md5PasswordAuth(salt, stream, buf, opts),
            .password => try passwordAuth(opts.password orelse "", stream, buf),
        }
    }

    {
        // if we're here, it's because we sent more data to the server (e.g. a password)
        // and we're now waiting for a reply, server should send a final auth ok message
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.UnexpectedDBMessage,
        }

        switch (try proto.AuthenticationRequest.parse(msg.data)) {
            .ok => return null,
            else => return error.UnexpectedDBMessage,
        }
    }
}

fn saslAuth(io: Io, req: proto.AuthenticationRequest.SASL, stream: *Stream, buf: *Buffer, reader: *Reader, opts: Opts) !?[]const u8 {
    var sasl_buf: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&sasl_buf);
    const allocator = fba.allocator();
    const binding = if (opts.channel_binding == .disable)
        null
    else
        try stream.channelBinding(allocator);
    const use_plus = binding != null and req.scram_sha_256_plus and
        opts.channel_binding != .disable;
    if (opts.channel_binding == .require) {
        if (binding == null) return error.ChannelBindingUnavailable;
        if (!req.scram_sha_256_plus) return error.ChannelBindingNotOffered;
    } else if (!use_plus and !req.scram_sha_256) {
        return error.UnexpectedDBMessage;
    }
    var sasl = try SASL.init(
        io,
        allocator,
        if (use_plus) binding else null,
        binding != null and opts.channel_binding != .disable,
    );

    {
        // send the client initial response
        const msg = proto.SASLInitialResponse{
            .response = sasl.client_first_message,
            .mechanism = if (use_plus) "SCRAM-SHA-256-PLUS" else "SCRAM-SHA-256",
        };
        buf.resetRetainingCapacity();
        try msg.write(buf);
        try stream.writeAll(buf.string());
    }

    {
        // read the server continue response
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.InvalidSASLFlow,
        }
        const c = try proto.AuthenticationSASLContinue.parse(msg.data);
        try sasl.serverResponse(c.data);
    }

    {
        // send the client final response
        const msg = proto.SASLResponse{
            .data = try sasl.clientFinalMessage(opts.password orelse ""),
        };
        buf.resetRetainingCapacity();
        try msg.write(buf);
        try stream.writeAll(buf.string());
    }

    {
        // read the server final response
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.InvalidSASLFlow,
        }
        const final = try proto.AuthenticationSASLFinal.parse(msg.data);
        try sasl.verifyServerFinal(final.data);
    }
    return null;
}

fn md5PasswordAuth(salt: []const u8, stream: *Stream, buf: *Buffer, opts: Opts) !void {
    var hash: [16]u8 = undefined;
    {
        var hasher = std.crypto.hash.Md5.init(.{});
        hasher.update(opts.password orelse "");
        hasher.update(opts.username);
        hasher.final(&hash);
    }

    {
        const hex_hash = std.fmt.bytesToHex(&hash, .lower);
        var hasher = std.crypto.hash.Md5.init(.{});
        hasher.update(&hex_hash);
        hasher.update(salt);
        hasher.final(&hash);
    }
    var hashed_password: [35]u8 = undefined;
    const password = try std.fmt.bufPrint(&hashed_password, "md5{s}", .{&std.fmt.bytesToHex(&hash, .lower)});
    try passwordAuth(password, stream, buf);
}

fn passwordAuth(password: []const u8, stream: *Stream, buf: *Buffer) !void {
    buf.resetRetainingCapacity();
    const pw = proto.PasswordMessage{ .password = password };
    try pw.write(buf);
    try stream.writeAll(buf.string());
}

const SASL = struct {
    allocator: Allocator,
    client_first_message: []u8,
    gs2_header_length: usize,
    channel_binding_data: ?[]const u8,
    auth_message: ?[]const u8 = null,
    salted_password: ?[32]u8 = null,
    server_response: ?ServerResponse = null,

    const Base64Encoder = std.base64.standard.Encoder;
    const Base64Decoder = std.base64.standard.Decoder;

    pub fn init(
        io: Io,
        allocator: Allocator,
        channel_binding_data: ?[]const u8,
        supports_channel_binding: bool,
    ) !SASL {
        var nonce: [18]u8 = undefined;
        std.Io.random(io, &nonce);

        const gs2_header = if (channel_binding_data != null)
            "p=tls-server-end-point,,"
        else if (supports_channel_binding)
            "y,,"
        else
            "n,,";
        var client_first_message = try allocator.alloc(u8, gs2_header.len + 5 + 24);
        @memcpy(client_first_message[0..gs2_header.len], gs2_header);
        @memcpy(client_first_message[gs2_header.len..][0..5], "n=,r=");
        _ = Base64Encoder.encode(client_first_message[gs2_header.len + 5 ..], &nonce);

        return .{
            .allocator = allocator,
            .client_first_message = client_first_message,
            .gs2_header_length = gs2_header.len,
            .channel_binding_data = channel_binding_data,
        };
    }

    pub fn serverResponse(self: *SASL, data: []const u8) !void {
        if (data.len < 8) {
            return error.InvalidLength;
        }

        // Specification states the attribute positions are fixed, so we expect r=X,s=Y,i=Z
        if (data[0] != 'r' or data[1] != '=') {
            return error.InvalidNoncePrefix;
        }

        const owned = try self.allocator.dupe(u8, data);

        var res = ServerResponse{
            .raw = owned,
            .nonce = undefined,
            .base64_salt = undefined,
            .iterations = undefined,
        };

        var pos: usize = 2;
        {
            const sep = std.mem.indexOfScalarPos(u8, owned, pos, ',') orelse return error.MissingSalt;
            res.nonce = owned[2..sep];
            pos = sep + 1;
        }

        {
            const value_start = pos + 2;
            if (owned.len < value_start or owned[pos] != 's' or owned[pos + 1] != '=') {
                return error.InvalidSaltPrefix;
            }
            pos = value_start;

            const sep = std.mem.indexOfScalarPos(u8, owned, pos, ',') orelse return error.MissingIterations;
            res.base64_salt = owned[pos..sep];
            pos = sep + 1;
        }

        {
            const value_start = pos + 2;
            if (owned.len < value_start or owned[pos] != 'i' or owned[pos + 1] != '=') {
                return error.InvalidIterationPrefix;
            }
            pos = value_start;
            const sep = std.mem.indexOfScalarPos(u8, owned, pos, ',') orelse owned.len;
            res.iterations = std.fmt.parseInt(u32, owned[pos..sep], 10) catch return error.InvalidIteration;
        }

        self.server_response = res;
    }

    pub fn clientFinalMessage(self: *SASL, password: []const u8) ![]const u8 {
        const sr = self.server_response orelse return error.MissingServerResponse;
        const allocator = self.allocator;

        const salt = blk: {
            const s = try allocator.alloc(u8, try Base64Decoder.calcSizeForSlice(sr.base64_salt));
            try Base64Decoder.decode(s, sr.base64_salt);
            break :blk s;
        };

        const binding_data = self.channel_binding_data orelse &.{};
        const binding_input = try allocator.alloc(u8, self.gs2_header_length + binding_data.len);
        @memcpy(binding_input[0..self.gs2_header_length], self.client_first_message[0..self.gs2_header_length]);
        @memcpy(binding_input[self.gs2_header_length..], binding_data);
        const encoded_binding = try allocator.alloc(u8, Base64Encoder.calcSize(binding_input.len));
        _ = Base64Encoder.encode(encoded_binding, binding_input);
        const unproved = try std.fmt.allocPrint(allocator, "c={s},r={s}", .{ encoded_binding, sr.nonce });
        const auth_message = try std.fmt.allocPrint(allocator, "{s},{s},{s}", .{
            self.client_first_message[self.gs2_header_length..],
            sr.raw,
            unproved,
        });
        const salted_password = blk: {
            var buf: [32]u8 = undefined;
            try std.crypto.pwhash.pbkdf2(&buf, password, salt, sr.iterations, std.crypto.auth.hmac.sha2.HmacSha256);
            break :blk buf;
        };

        const proof = blk: {
            var client_key: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&client_key, "Client Key", &salted_password);

            var stored_key: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&client_key, &stored_key, .{});

            var client_signature: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&client_signature, auth_message, &stored_key);

            var proof: [32]u8 = undefined;
            for (client_key, client_signature, 0..) |ck, cs, i| {
                proof[i] = ck ^ cs;
            }

            var encoded_proof: [44]u8 = undefined;
            _ = Base64Encoder.encode(&encoded_proof, &proof);
            break :blk encoded_proof;
        };

        self.auth_message = auth_message;
        self.salted_password = salted_password;
        return std.fmt.allocPrint(allocator, "{s},p={s}", .{ unproved, proof });
    }

    pub fn verifyServerFinal(self: *SASL, data: []const u8) !void {
        if (data.len < 46) {
            return error.InvalidLength;
        }
        const auth_message = self.auth_message orelse return error.MissingAutMessage;
        const salted_password = if (self.salted_password) |*sp| sp else return error.MissingSaltedPassword;

        const computed_signature = blk: {
            var server_key: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&server_key, "Server Key", salted_password);

            var server_signature: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&server_signature, auth_message, &server_key);

            var encoded_signature: [44]u8 = undefined;
            _ = Base64Encoder.encode(&encoded_signature, &server_signature);
            break :blk encoded_signature;
        };

        // don't tell me about timing leaks unless there's also something in std to deal with it
        if (std.mem.eql(u8, &computed_signature, data[2..]) == false) {
            return error.InvalidServerSignature;
        }
    }
};

pub const ServerResponse = struct {
    raw: []const u8,
    nonce: []const u8,
    base64_salt: []const u8,
    iterations: u32,
};

const t = @import("lib.zig").testing;
test "SASL: init" {
    defer t.reset();
    var sasl1 = try SASL.init(t.io, t.arena.allocator(), null, false);

    try t.expectString("n,,n=,r=", sasl1.client_first_message[0..8]);

    var sasl2 = try SASL.init(t.io, t.arena.allocator(), null, false);
    try t.expectString("n,,n=,r=", sasl2.client_first_message[0..8]);

    var sasl3 = try SASL.init(t.io, t.arena.allocator(), null, false);
    try t.expectString("n,,n=,r=", sasl3.client_first_message[0..8]);

    var sasl4 = try SASL.init(t.io, t.arena.allocator(), null, false);
    try t.expectString("n,,n=,r=", sasl4.client_first_message[0..8]);

    // The nonce should be random. It's unlikely that if we generate 4, we'd get
    // the same value at a given byte.
    const nonce1 = sasl1.client_first_message[8..];
    const nonce2 = sasl2.client_first_message[8..];
    const nonce3 = sasl3.client_first_message[8..];
    const nonce4 = sasl4.client_first_message[8..];
    for (0..18) |i| {
        try t.expectEqual(true, nonce1[i] != nonce2[i] or
            nonce2[i] != nonce3[i] or
            nonce1[i] != nonce3[i] or
            nonce3[i] != nonce4[i] or
            nonce1[i] != nonce4[i] or
            nonce2[i] != nonce4[i]);
    }
}

test "SASL: serverResponse invalid" {
    //invalid response
    const InvalidTest = struct {
        input: []const u8,
        expected: anyerror,
    };

    const test_cases = [_]InvalidTest{
        .{ .input = "", .expected = error.InvalidLength },
        .{ .input = "r", .expected = error.InvalidLength },
        .{ .input = "r=", .expected = error.InvalidLength },
        .{ .input = "s=abc,r=123,i=32", .expected = error.InvalidNoncePrefix },
        .{ .input = "r=abc123,i=32,s=aaa", .expected = error.InvalidSaltPrefix },
        .{ .input = "r=abc123,s=aaa,x=32", .expected = error.InvalidIterationPrefix },
        .{ .input = "r=abc123", .expected = error.MissingSalt },
        .{ .input = "r=abc123,s=aaaa", .expected = error.MissingIterations },
        .{ .input = "r=abc123,s=aaaa,i=123a", .expected = error.InvalidIteration },
    };

    defer t.reset();
    var sasl = try SASL.init(t.io, t.arena.allocator(), null, false);

    for (test_cases) |tc| {
        try t.expectError(tc.expected, sasl.serverResponse(tc.input));
        try t.expectEqual(null, sasl.server_response);
    }
}

test "SASL: serverResponse" {
    defer t.reset();
    var sasl = try SASL.init(t.io, t.arena.allocator(), null, false);

    try sasl.serverResponse("r=abc123,s=aaaaxa,i=4096");
    try t.expectString("abc123", sasl.server_response.?.nonce);
    try t.expectString("aaaaxa", sasl.server_response.?.base64_salt);
    try t.expectEqual(4096, sasl.server_response.?.iterations);
}

test "SASL: PLUS binds the TLS server endpoint into the proof" {
    defer t.reset();
    const binding = [_]u8{ 1, 2, 3 };
    var sasl = try SASL.init(t.io, t.arena.allocator(), &binding, true);
    try t.expectString(
        "p=tls-server-end-point,,n=,r=",
        sasl.client_first_message[0..29],
    );
    const server_nonce = try std.fmt.allocPrint(
        t.arena.allocator(),
        "{s}server",
        .{sasl.client_first_message[sasl.gs2_header_length + 5 ..]},
    );
    const response = try std.fmt.allocPrint(
        t.arena.allocator(),
        "r={s},s=QSXCR+Q6sek8bf92,i=4096",
        .{server_nonce},
    );
    try sasl.serverResponse(response);
    const final = try sasl.clientFinalMessage("password");
    try t.expectEqual(true, std.mem.startsWith(
        u8,
        final,
        "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAQID,r=",
    ));
}

test "SASL: supported channel binding signals a non-PLUS server" {
    defer t.reset();
    var sasl = try SASL.init(t.io, t.arena.allocator(), null, true);
    try t.expectString("y,,n=,r=", sasl.client_first_message[0..8]);
    try t.expectEqual(@as(usize, 3), sasl.gs2_header_length);
}
