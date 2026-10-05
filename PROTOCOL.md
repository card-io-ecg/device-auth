Device auth protocol
====================

A device registers its own P-256 public key with a one-time pairing code, and then signs each
request with that key. The server stores only public keys, so nothing it holds can sign as a device.

This document is the normative wire format. `device-auth-firmware` produces it and
`device-auth-server` consumes it. Sections marked *recommendation* describe server policy that a
server may change without breaking devices.

The key words "must", "must not", "should", and "may" are used as RFC 2119 describes.

## Conventions

- **base64url** is RFC 4648 §5 base64url without `=` padding.
- **JSON** is RFC 8259, encoded as UTF-8.
- **Public key** is the 65-byte uncompressed SEC1 encoding of a P-256 point: `0x04`, then the
  32-byte big-endian `x` coordinate, then the 32-byte big-endian `y` coordinate.
- **JWS** is the RFC 7515 compact serialization: `base64url(header) "." base64url(payload) "."
  base64url(signature)`. The signing input is the ASCII bytes of
  `base64url(header) "." base64url(payload)`.
- **ES256** is ECDSA over P-256 with SHA-256, as RFC 7518 §3.4 describes. The signature is 64 bytes:
  the 32-byte big-endian `r`, then the 32-byte big-endian `s`.

A device must derive ECDSA nonces deterministically, as RFC 6979 describes. The server cannot check
this. It keeps the key safe when the device's random source is weak.

## Device name

A device name is 1 to 32 bytes. Each byte is an ASCII letter, an ASCII digit, or `-`.

## Pairing code

A pairing code is 10 characters from the 32-character alphabet:

```text
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

This 10-character string is the **canonical code**. It is shown to a person as two groups of five
joined by `-`, such as `7KQ2M-X9D4F`.

The server generates each character from one uniformly random byte: the low 5 bits of the byte are
the index into the alphabet. A code carries 50 bits.

### Typed codes

A person types the code on the device. The device turns the typed text into the canonical code:

1. `-` and space are dropped.
2. `O` and `o` become `0`. `I`, `i`, `L`, and `l` become `1`.
3. Other ASCII letters become upper case.
4. Any remaining character outside the alphabet rejects the input.
5. The result must be exactly 10 characters.

The server compares canonical codes only.

### Code policy (recommendation)

A code is valid for 10 minutes and is used up by one successful registration. Several codes may be
pending at once. The server stores each pending code in canonical form until it is used or expires,
because it needs the code to check `code_mac`.

## Registration

The device generates a P-256 key pair and keeps the private key. It sends a JWS signed with that
private key. Over HTTP the device sends the JWS as the request body with
`Content-Type: application/jwt`.

Header:

```json
{"alg":"ES256","typ":"JWT","jwk":{"kty":"EC","crv":"P-256","x":"…","y":"…"}}
```

`x` and `y` are the base64url encodings of the 32-byte coordinates of the device's public key.

Payload:

```json
{"name":"…","code_mac":"…"}
```

| Claim | Value |
|---|---|
| `name` | The device name the device chooses |
| `code_mac` | base64url of HMAC-SHA256 over the 65-byte public key, keyed with the ASCII bytes of the canonical code |

The signature is ES256 over the signing input, made with the private key that belongs to `jwk`.

### Server checks

The server accepts a registration when all of these hold:

1. The header is readable, `alg` is `ES256`, and `jwk` is an EC key on P-256 whose `x` and `y` each
   decode to 32 bytes and form a point on the curve.
2. `name` is a JSON string and a valid device name. `code_mac` is a JSON string that decodes to
   32 bytes.
3. The signature verifies with the key in `jwk`.
4. `code_mac` equals the HMAC computed with a pending, unexpired code.

A failure in steps 1 or 2 is a **malformed registration**. A failure in step 3 or 4 is an
**unauthorized registration**. A registration that passes all four but names a device that is
already registered is a **name conflict**, and the code stays pending.

The code is checked only through the HMAC. Someone who records a registration can test guesses
offline, but by then the registration has used the code up. Someone who blocks a registration has
to guess a 50-bit code within its lifetime to redirect it to another key.

### Test vector

| Input | Value |
|---|---|
| Private key scalar | 32 bytes of `0x01` |
| Public key | `046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a` |
| `jwk` `x` | `b_A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhY` |
| `jwk` `y` | `PE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo` |
| Canonical code | `7KQ2MX9D4F` |
| HMAC-SHA256 | `e01fa59c548b165d92e9c59607121d25f69ee5079303a3ee829bc0dcb4acc36e` |
| `code_mac` | `4B-lnFSLFl2S6cWWBxIdJfae5QeTA6PugpvA3LSsw24` |

## Request token

Every request that needs a device's identity carries a request token. Over HTTP the device sends
it as `Authorization: Bearer {token}`.

Header:

```json
{"alg":"ES256","typ":"JWT"}
```

Payload, with each claim required and each a JSON string:

| Claim | Value |
|---|---|
| `sub` | The device's registered name |
| `jti` | The request counter in decimal, from `1` to `9223372036854775807`, with no sign and no leading zeros |
| `htm` | The request method, such as `GET` |
| `htu` | The request path and query, exactly as the server receives them, such as `/items?page=2` |

The signature is ES256 over the signing input, made with the device's registered key.

The device writes the claims in the order above. String values are JSON-escaped: `"` becomes
`\"`, `\` becomes `\\`, and each character from U+0000 to U+001F becomes `\u00` followed by two
lowercase hexadecimal digits. No other character is escaped. The server parses the payload as JSON,
so it does not depend on claim order or escaping style.

The server ignores other claims and does not check `typ`. The token carries no expiry, and the
server checks no time.

### Server checks

The server accepts a request token when all of these hold:

1. `sub` is readable from the unverified payload and is a registered device name.
2. `alg` is `ES256`, and the signature verifies with that device's public key.
3. `jti`, `htm`, and `htu` are present and are JSON strings. `jti` is in range and has the decimal
   form above.
4. `htm` equals the request method, and `htu` equals the request path and query as the server
   received them.
5. `jti` is greater than the counter the server stores for this device and request class, as
   **Counters** describes.

A failure in steps 1 to 4 is a **rejected request**. A failure in step 5 alone is a
**stale counter**.

## Counters

The server defines its **request classes**, such as one class for each method and route template,
and documents them for its devices. It keeps one counter for each device and request class. A
counter that was never written is `0`.

A request is accepted when its `jti` is greater than the stored counter. Accepting it sets the
stored counter to that `jti`. Comparing and setting must be one atomic step.

When `jti` is not greater than the stored counter, the server refuses the request with the
response header:

```text
X-Request-Counter: {counter}
```

`{counter}` is the stored counter in decimal. `0` is written `0`. Other values have no sign and no
leading zeros. Every other refusal omits `X-Request-Counter`.

The device keeps one counter for each request class. It starts at `0` and adds one before each
request, so its first request sends `jti` `1`. After a stale-counter refusal it sets its counter to
the header's value, and its next request sends that value plus one. A device that lost its counters
recovers this way from the first refusal of each class.

A device sends requests of one class one at a time. Requests of different classes may be in flight
together.

A captured request token is valid until the server accepts a greater `jti` for that device and
class.

## Server answers (recommendation)

| Outcome | HTTP answer |
|---|---|
| Registration body is not UTF-8, or `Content-Type` is not `application/jwt` | `400` |
| Malformed registration | `400` |
| Unauthorized registration | `401` |
| Name conflict | `409`, and the code stays pending |
| Registered | `201`, and the code is used up |
| No `Authorization` header, or not `Bearer {token}` | `401` |
| Rejected request | `401` |
| Stale counter | `401` with `X-Request-Counter` |

The server should not write the `Authorization` header, a request token, or a registration body to
its logs.

## Transport

On plain HTTP, request and response content stays readable on the network. A request token is bound
to one method, path, and counter, so it cannot be reused for any other request. A registration
cannot be redirected to another key without the code.
