// Browser side of passkey ceremonies. The server sends and expects the JSON forms of the
// WebAuthn options and credentials, with binary fields in Base64url.

type Json = Record<string, unknown>

export function passkeysSupported() {
  return typeof window !== "undefined" && window.isSecureContext !== false && typeof window.PublicKeyCredential === "function" && Boolean(navigator.credentials)
}

/** True when the user dismissed the browser prompt or it timed out, which needs no error message. */
export function passkeyCancelled(error: unknown) {
  return error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")
}

export function toBytes(value: string) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/")
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="))
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

export function toBase64Url(buffer: ArrayBuffer | ArrayBufferView) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] {
  return ((list as Array<{ id: string; transports?: AuthenticatorTransport[] }>) || []).map((item) => ({
    type: "public-key",
    id: toBytes(item.id),
    ...(item.transports?.length ? { transports: item.transports } : {}),
  }))
}

/** Asks the browser to create a passkey and returns the credential in the form the server reads. */
export async function createPasskey(options: { publicKey: Json }) {
  const publicKey = options.publicKey as Json & { user: Json & { id: string }; challenge: string }
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...(publicKey as unknown as PublicKeyCredentialCreationOptions),
      challenge: toBytes(publicKey.challenge),
      user: { ...(publicKey.user as unknown as PublicKeyCredentialUserEntity), id: toBytes(publicKey.user.id) },
      excludeCredentials: descriptors(publicKey.excludeCredentials),
    },
  })) as PublicKeyCredential | null
  if (!credential) throw new DOMException("No credential was created", "NotAllowedError")
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
      transports: typeof response.getTransports === "function" ? response.getTransports() : [],
    },
  }
}

/** Asks the browser for a passkey assertion and returns it in the form the server reads. */
export async function getPasskey(options: { publicKey: Json }) {
  const publicKey = options.publicKey as Json & { challenge: string }
  const credential = (await navigator.credentials.get({
    publicKey: {
      ...(publicKey as unknown as PublicKeyCredentialRequestOptions),
      challenge: toBytes(publicKey.challenge),
      allowCredentials: descriptors(publicKey.allowCredentials),
    },
  })) as PublicKeyCredential | null
  if (!credential) throw new DOMException("No credential was chosen", "NotAllowedError")
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
    },
  }
}

export type PasskeyAttestation = Awaited<ReturnType<typeof createPasskey>>
export type PasskeyAssertion = Awaited<ReturnType<typeof getPasskey>>
