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

The result cipertexts are called _**texcrets**_. You can load many secrets before encrypting,
then it will be possible to read the resulting *texcret* with any of the secret.

To decrypt *texcrets* you need to load at least one of the secrets.

You can place your *texcrets* anywhere on your HTML page. Add then to the end of your page this line:

```html
<script defer src="https://aleksandr.vin/texcret/texcret.js" onload="Texcret.magic();"></script>
```

And when page loads, perform this click pattern on any *texcret*: *dblclick - click - dblclick*. And magic will happen ! 🪄

Want to encrypt/decrypt or _texcret/detexcret_ files from CLI? — Possible, see below.

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

This will be used for the *texcret* CLI tool and for local demo web app.

Also can be handy to trust that CA on your iPhone (for development and home use). Send *rootCA.pem* to your iPhone from:

    cd $(mkcert -CAROOT)

Then on your iPhone:

1. Go to **Settings → General → VPN & Device Management** (or **Profiles & Device Management**).
2.	Tap the downloaded profile and install it.
3.	Go to **Settings → General → About → Certificate Trust Settings**.
4.	You’ll see your mkcert root listed (something like “mkcert development CA”).
5.	Toggle **Enable Full Trust for Root Certificates** ON for that CA.

Then, on your mac again, you ca start a demo web app:

    ./web.sh

That will open an https-served page (see [public/index.html](public/index.html)), you can open it on your iPhone
or continue on mac.

If you want to access a demo page (same as live demo [https://aleksandr.vin/texcret/demo.html](https://aleksandr.vin/texcret/demo.html)),
you can add `demo.html` to the url that was opened when `./web.sh` was started.

## CLI

There is a handy cli tool, that can do many ways of encryption-decryption. It will need
secrets to operate, so let's start with this.

### Load secrets

Loading secrets for specific origin is possible only in browser at a page from that origin.
The CLI tool starts a temporary web-server on https://localhost:8443, and
opens browser pointing to a special bridge page that should be hosted on the origin. It looks like the demo page.
On this bridge page you can load your secret(s): authenticate using platform passkeys, yubikeys or passwords.
Then all these secrets are self-encrypted and sent to CLI locally via https://localhost:8443. CLI tool will store them (encrypted) as *texcret* in *~/.config/texcrets/secrets.json*.

The command to load the secrets is this:

    texcret load-secrets --origin https://aleksandr.vin --bridge-base-path /texcret

Check help for options. You'll need cert and key for the local server, see *Running locally* section above in this documentation.

Beware that bridge page will self-encrypt secrets, so to use them you'll need to posess at lease one secret.
That could be an extra one password you loaded on the bridge page before sending secrets to back CLI and then you provide this exact password for the commands that use these secrets.
You can also force excluding that password from use in encryption/decryption with `--no-arg-passwords`.

### List secrets

Once you loaded secrets, you can list them with:

    texcret list-secrets --origin https://aleksandr.vin

### Encrypt files locally

Encryption is done with:

    texcret encrypt --origin https://aleksandr.vin --password - file.tar.gz

Which will create a *file.tar.gz.enc*.

### Decrypt files locally

Decryption is done with:

    texcret decrypt --origin https://aleksandr.vin --password - file.tar.gz.enc

### Create *texcrets* in files

You markup blocks that you wish to encrypt like:

```
{% texcret %}
This text must be secured
{% endtexcret %}
```

Then you run:

    texcret texcret --origin https://aleksandr.vin --password - --in-file docs.md

It will replace markup blocks with *texcret* blocks, see next section on how to *detexcret* them back.

### *Detexcret* blocks like

*Texcret* blocks like:

```
[Texcret start]: #

WUtMQjIAc2vr8vrPlGwcf1DaAAMtLS0ABpnB4rrZn/0Ae8d471Q5mWzGpQRPFmHvlaMjHnoAMD21
TJB/CwLiGpqRHIckFUA/bIVQN2o+jWjSWwwo2OPSNrTEScUPGe/jlMnbNdvrvvc6dgfds4nuUWdV
6oYuEEJuaYARdY7u1FiKPy4AMHNJdyZTImGQjpb7gvP7JfhbAw98XpLMfkxEsVByJJTJwuWL+gIZ
pnLZEsYZtFd1tsTTBV0Un1ZrfQVNgn8PtMdJbFrjiJgL8FdLCEUAMM5fyA0/lRerudUy5jIvtSLE
rjdq6QhbPosN579V/BiKrRrN6i15cg/g/mssMi8KqFYdcGEbLRGgjT0xObMX/4BIUJ/oEXjIi6PI
5bsAMNG4GCMza9rRna+gShAVeZXx1wMnvymK+VgygVHblw7Nbm4GdAeUd3DQqrZGXNkrAibE23Oi
wb6GddE2IRb60HmSn+0xd49Hjy/LRDAAMGH/rTQ21b80Apsuu132tMK4qkxmPTeMkGF7fkwdFOY6
5nhA30ZqHEG9lgmT9VpJsO8WCeV6hD7DUoKL1/jgl4nZaSBVl4ST1lJn/JUAMAF9wBPAs3TrBqTa
O96JMcjpJe+oVJbCTIy3RixQNDeHsoVUpdZTMjXwVV5yHGM/etVPK42JfNclt5qwq7aLSR6A9Zyg
u1ltNpoJKAHEekHqBLOjk/f/ZOiegu5NBiHH7eLjGA==

[Texcret end]: #
```

Can be *detexcreted* with reverse call:

    texcret detexcret --origin https://aleksandr.vin --password - --in-file docs.md

That should render the original file.
