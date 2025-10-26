# Texcret — from Tex(t Se)cret

PoC for the encryption/decryption happenning on web page. No server communication, no OS communication.

Page loads from server with encrypted payload. Then device can go offline.
User authenticates **ON THE PAGE** with Yubikey: no remote calls to servers are made.
Page reads a secret key from the Yubikey credentials (securely stored on Yubikey per registered credential:
User x Relying Party x Page Origin) and decrypts the payload on the page.
When user wants to hide page payload again, they refresh or close the page.

## Live demo

Go to [https://aleksandr.vin/texcret/demo.html](https://aleksandr.vin/texcret/demo.html) for live demo.

## Usage

To encrypt texts we'll need secrets. Secrets are loaded **ON THE PAGE** from
Yubikey [largeBlob](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Large-Blob-Extension), passkey or password.

The result cipertexts are called _**texcrets**_.

To decrypt *texcrets* you need to load at least one of the secrets.

You can place your *texcrets* anywhere on your HTML page. Add then to the end of your page:

```html
<script defer src="https://aleksandr.vin/texcret/texcret.js" onload="Texcret.magic();"></script>
```

Then when page loads, perform this click pattern on any *texcret* on the page: *dblclick - click - dblclick*. And magic will happen ! 🪄

## Secrets providers

All secrets except passwords are bond to origin of the page, works in secure context (over HTTPS). So you'll need to register key from the same origin, which
you plan to use them.

### Yubikey

You'll need Yubikey 5C NFC with fw 5.7+, which support largeBlobs.

You can check for support with something like this:

    brew install libfido2
    fido2-token -L
    fido2-token -I ioreg://4337239362 | grep largeBlobs

You want to see smth. like:

```
options: ... largeBlobs ...
```

Then Yubikey supports FIDO2 CTAP 2.1 features (✅ firmware ≥ 5.7).

### Passkey

If you don't have a Yubikey that supports largeBlobs, you can use platform's passkey.

**NOTE that iOS will share passkey to your devices via iCloud.**

### Password

If you want you can use password as well.


## Running locally

Create local cert:

    mkcert -install
    mkcert $(hostname) localhost 127.0.0.1 ::1

Send *rootCA.pem* to your iPhone from:

    cd $(mkcert -CAROOT)

Then on your iPhone:

1. Go to **Settings → General → VPN & Device Management** (or **Profiles & Device Management**).
2.	Tap the downloaded profile and install it.
3.	Go to **Settings → General → About → Certificate Trust Settings**.
4.	You’ll see your mkcert root listed (something like “mkcert development CA”).
5.	Toggle **Enable Full Trust for Root Certificates** ON for that CA.

Then on your mac again:

    ./web.sh

That will open an https-served page (see [public/index.html](public/index.html)), you can open it on your iPhone
or continue on mac.