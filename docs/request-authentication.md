# Authenticated diagnostic requests

V0.2 supports standard DSSE envelopes signed with Ed25519. DSSE binds both the
payload type and exact request bytes. DiagPermit deliberately keeps signature
validity separate from trust: a mathematically valid signature is not proof that
the signer is authorized to represent the named requester.

## Create local key material

```bash
diagpermit request keygen \
  --private-key requester-private.pem \
  --trust-store requester-trust.json \
  --key-id example-support-2026 \
  --identity security@example.test \
  --requester "Example Support"
```

Keep the private key secret. The generated JSON is a local trust-store template
containing only public material and the requester name authorized for that key.
Review it before distributing or installing it.

## Sign and verify

```bash
diagpermit request sign diagpermit.yaml request.dsse.json \
  --private-key requester-private.pem --key-id example-support-2026

diagpermit request verify request.dsse.json \
  --trust-store requester-trust.json
```

Possible results are:

- `REQUESTER VERIFIED`: signature and local requester policy passed.
- `SIGNATURE VALID — IDENTITY NOT TRUSTED`: cryptography passed, policy did not.
- `SIGNATURE NOT VERIFIED`: no matching local public key exists.
- `UNSIGNED`: the input is a valid request without a signature.
- `SIGNATURE INVALID`: a matching key was available but verification failed, or
  the envelope/payload was malformed.

The trust store is local policy, not part of DSSE and not embedded in the
diagnostic request. DiagPermit does not claim Sigstore identity verification in
V0.2.
