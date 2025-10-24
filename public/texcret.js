/*
 * Tex(t Se)cret
 *
 * Reference:
 * https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Large-Blob-Extension
 */

window.Texcret = {
  VERSION: "0.1.0",

  log(...a) { console.log(a.join(" ")); },
  enc: new TextEncoder(),
  dec: new TextDecoder(),
  b64(ab) { return btoa(String.fromCharCode(...new Uint8Array(ab))); },
  ubuf(b64s) { return Uint8Array.from(atob(b64s), c => c.charCodeAt(0)).buffer; },
  be16(n) { return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]); },
  readBE16(u8, off) { return (u8[off] << 8) | u8[off + 1]; },
  randBytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; },

  _secretsB64: [], // loaded from largeBlob on authenticate

  // Default RP/user (can be overridden via setters)
  rp: null, // { id: location.hostname, name: "Tex(t Se)cret Amnesiac" },
  user: null, // { id: null, name: "", displayName: "" },

  setRPName(name) {
    this.rp = { id: location.hostname, name };
  },

  setUser(name, displayName) {
    this.user = { id: this.randBytes(16), name, displayName };
  },

  // ---- Registration: create credential AND write largeBlob (32-byte secret)
  async registerNewCredentialAndLoadSecret(onSecretLoaded) {
    if (!this.rp) {
      this.log("❌ Registration impossible, set RP first.");
    }
    if (!this.user) {
      this.log("❌ Registration impossible, set user first.");
    }
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: this.randBytes(32),
        rp: this.rp,
        user: this.user,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
        authenticatorSelection: {
          // authenticatorAttachment: "platform",
          residentKey: "preferred",
          userVerification: "preferred",
        },
        timeout: 60000,
        attestation: "none",
        extensions: { largeBlob: { support: "required" } },
      }
    });

    const credentialIdB64 = this.b64(cred.rawId);
    // localStorage.setItem('credIdB64', credentialIdB64);
    this.log("✅ Registered credential. ID:", credentialIdB64);

    if (!cred.getClientExtensionResults().largeBlob) {
      this.log("❌ Large blob not supported by the user agent.");
      return;
    } else {
      this.log("✅ Large blob is supported by the user agent.");
    }

    try {
      const secret = this.randBytes(32); // store this in largeBlob
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: this.randBytes(32),
          // allowCredentials: [{ type: "public-key", id: this.ubuf(credentialIdB64) }],
          userVerification: "preferred",
          timeout: 60000,
          extensions: { largeBlob: { write: new Uint8Array(secret) } },
        }
      });

      if (assertion.getClientExtensionResults().largeBlob.written) {
        // demo-only: keep plaintext copy in memory
        this._secretsB64.push(this.b64(secret.buffer));
        onSecretLoaded && onSecretLoaded();
        this.log("🔐 Secret (32B) written to largeBlob.");
      } else {
        this.log("❌ The large blob could not be written");
      }
    } catch (e) {
      this.log("❌ Secret store failed:", e.message); console.error(e);
    }
  },

  // ---- Authentication: get assertion AND read largeBlob back
  async authenticateAndLoadSecret(onSecretLoaded) {
    const publicKey = {
      challenge: this.randBytes(32),
      // allowCredentials: [{ type: "public-key", id: this.ubuf(credentialIdB64) }],
      userVerification: "preferred",
      timeout: 60000,
      extensions: { largeBlob: { read: true } },
    };

    try {
      const assertion = await navigator.credentials.get({ publicKey });
      const clientExt = assertion.getClientExtensionResults();
      if (clientExt && clientExt.largeBlob && clientExt.largeBlob.blob) {
        this._secretsB64.push(this.b64(clientExt.largeBlob.blob)); // ArrayBuffer -> b64
        onSecretLoaded && onSecretLoaded();
        this.log("✅ Authenticated. Read secret from largeBlob (" + clientExt.largeBlob.blob.byteLength + " bytes).");
      } else {
        this.log("⚠️ Auth OK but largeBlob read not returned (not supported or not present).");
      }
    } catch (e) {
      this.log("❌ Authentication failed:", e.message); console.error(e);
    }
  },

  /* ===== Key derivation (HKDF-SHA256) from largeBlob secret ===== */
  async deriveAesKey(secretRaw, salt) {
    const ikm = await crypto.subtle.importKey("raw", secretRaw, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: this.enc.encode("YK-largeBlob-text") },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  /* ====== Header v2 (multiple recipients) ======
   * MAGIC: "YKLB2\0" (6 bytes)
   * 0..5     : MAGIC
   * 6..17    : dataIv (12 bytes)
   * 18..19   : nameLen (uint16 BE)
   * 20..(20+nameLen-1): filename UTF-8
   * next 2   : recipCount (uint16 BE)
   * For each recipient:
   *   salt (16), wrapIv (12), wrapLen (uint16), wrappedKey (wrapLen)
   * After recipients: ciphertext (AES-GCM over plaintext using dataKey & dataIv)
   */
  MAGIC2: new Uint8Array([0x59, 0x4b, 0x4c, 0x42, 0x32, 0x00]), // "YKLB2\0"

  makeHeaderV2(dataIv, name, recipEntries) {
    const nameUtf8 = this.enc.encode(name);
    const nameLen = nameUtf8.length;

    let size = 6 + 12 + 2 + nameLen + 2;
    for (const r of recipEntries) {
      size += 16 + 12 + 2 + r.wrappedKey.length;
    }

    const head = new Uint8Array(size);
    let off = 0;

    head.set(this.MAGIC2, off); off += 6;
    head.set(dataIv, off); off += 12;
    head.set(this.be16(nameLen), off); off += 2;
    head.set(nameUtf8, off); off += nameLen;

    head.set(this.be16(recipEntries.length), off); off += 2;

    for (const r of recipEntries) {
      head.set(r.salt, off); off += 16;
      head.set(r.wrapIv, off); off += 12;
      head.set(this.be16(r.wrappedKey.length), off); off += 2;
      head.set(r.wrappedKey, off); off += r.wrappedKey.length;
    }
    return head;
  },

  parseHeaderV2(u8) {
    for (let i = 0; i < 6; i++) {
      if (u8[i] !== this.MAGIC2[i]) throw new Error("Bad magic / not a YKLB2 file");
    }
    let off = 6;
    const dataIv = u8.slice(off, off + 12); off += 12;

    const nameLen = this.readBE16(u8, off); off += 2;
    const nameBytes = u8.slice(off, off + nameLen); off += nameLen;
    const name = this.dec.decode(nameBytes);

    const recipCount = this.readBE16(u8, off); off += 2;
    const recipients = [];
    for (let i = 0; i < recipCount; i++) {
      const salt = u8.slice(off, off + 16); off += 16;
      const wrapIv = u8.slice(off, off + 12); off += 12;
      const wrapLen = this.readBE16(u8, off); off += 2;
      const wrappedKey = u8.slice(off, off + wrapLen); off += wrapLen;
      recipients.push({ salt, wrapIv, wrappedKey });
    }

    return { dataIv, name, recipients, bodyOffset: off };
  },

  /* ====== Encrypt flow ====== */
  async encrypt(pt, name) {
    try {
      // 1) fresh AES-GCM-256 data key
      const dataKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        /* extractable */ true,
        ["encrypt", "decrypt"]
      );
      const dataKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", dataKey)); // 32 bytes
      const dataIv = this.randBytes(12);

      // 2) encrypt plaintext
      const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv: dataIv }, dataKey, pt)
      );

      // 3) wrap dataKeyRaw for each secret
      const recipEntries = [];
      for (const secretB64 of this._secretsB64) {
        const secretRaw = this.ubuf(secretB64);
        const salt = this.randBytes(16);
        const wrapIv = this.randBytes(12);
        const wrapKey = await this.deriveAesKey(secretRaw, salt);
        const wrappedKey = new Uint8Array(
          await crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapIv }, wrapKey, dataKeyRaw)
        );
        recipEntries.push({ salt, wrapIv, wrappedKey });
      }

      // 4) header + output
      const header = this.makeHeaderV2(dataIv, name, recipEntries);
      const out = new Uint8Array(header.length + ct.length);
      out.set(header, 0);
      out.set(ct, header.length);

      this.log("🔒 Encrypted with a fresh data key and wrapped for", recipEntries.length, "recipient(s).");
      this.log("iv (data):", this.b64(dataIv.buffer));
      this.log("name:", name);
      return out;
    } catch (e) {
      this.log("❌ Encrypt error:", e.message);
    }
  },

  /* ====== Decrypt flow (tries all secrets & recipients) ====== */
  async decrypt(data) {
    try {
      const { dataIv, name, recipients, bodyOffset } = this.parseHeaderV2(data);
      const ct = data.slice(bodyOffset);

      this.log("name:", name);
      this.log("recipients in header:", recipients.length);

      // Try to unwrap the data key using each provided secret against each recipient
      let dataKey = null;

      outer:
      for (const secretB64 of this._secretsB64) {
        const secretRaw = this.ubuf(secretB64);
        for (const r of recipients) {
          try {
            const wrapKey = await this.deriveAesKey(secretRaw, r.salt);
            const dataKeyRaw = new Uint8Array(
              await crypto.subtle.decrypt({ name: "AES-GCM", iv: r.wrapIv }, wrapKey, r.wrappedKey)
            );
            dataKey = await crypto.subtle.importKey(
              "raw",
              dataKeyRaw,
              { name: "AES-GCM" },
              false,
              ["decrypt"]
            );
            this.log("✅ Unwrapped data key with one of your secrets.");
            break outer;
          } catch (_) {
            this.log("🔁 Wrong secret for this recipient; keep trying.");
          }
        }
      }

      if (!dataKey) {
        throw new Error("None of the provided secrets could unwrap the data key.");
      }

      const ptBuf = new Uint8Array(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv: dataIv }, dataKey, ct)
      );

      this.log("🔓 Decrypted file name:", name);
      return { buffer: ptBuf, name };
    } catch (e) {
      this.log("❌ Decrypt error:", e.message);
    }
  },
};