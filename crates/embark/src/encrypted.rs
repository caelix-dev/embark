use alloc::string::String;
use alloc::vec::Vec;
use embark_format::Error;

/// Type-state marker selecting [`EncryptedFile`]'s build-time
/// embedded-key mode -- the default, so plain `EncryptedFile` means
/// `EncryptedFile<EmbeddedKey>`. See the [type-level docs](EncryptedFile)
/// for what that means and its obfuscation-not-security caveat.
pub struct EmbeddedKey;

/// Type-state marker selecting [`EncryptedFile`]'s runtime-key mode. See
/// the [type-level docs](EncryptedFile) for what that means.
pub struct RuntimeKey;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::EmbeddedKey {}
    impl Sealed for super::RuntimeKey {}
}

/// The set of [`EncryptedFile`] key modes: [`EmbeddedKey`] and
/// [`RuntimeKey`], and nothing else.
///
/// Sealed on purpose — the two modes differ in what an `EncryptedFile`
/// actually stores, which [`KeySource`](KeyMode::KeySource) names, and the
/// crate relies on that being exactly these two.
pub trait KeyMode: sealed::Sealed {
    /// What a handle in this mode carries besides the sealed entry.
    ///
    /// For [`EmbeddedKey`] it is the macro-generated key-reconstruction
    /// function; for [`RuntimeKey`] it is `()`, so a runtime-key handle has
    /// nowhere to put key material even as a placeholder.
    type KeySource: Copy;
}

impl KeyMode for EmbeddedKey {
    type KeySource = fn() -> [u8; 32];
}

impl KeyMode for RuntimeKey {
    type KeySource = ();
}

/// An encrypted, embedded file, produced by [`embed_crypt!`](crate::embed_crypt)
/// or `#[embark(encrypt)]`.
///
/// `embark` supports two distinct encryption modes, kept apart **at the
/// type level** by the `K` type parameter -- [`EmbeddedKey`] (the default)
/// or [`RuntimeKey`] -- so they cannot be confused. Each mode exposes only
/// the methods that make sense for it: calling the wrong decrypt method
/// for a handle's mode is a **compile error**, not a runtime panic.
///
/// - **`EncryptedFile<EmbeddedKey>`** (the default; plain `EncryptedFile`
///   means this) — built with
///   [`with_embedded_key`](EncryptedFile::with_embedded_key). The key is
///   generated at build time and reassembled at runtime by a
///   reconstruction function the macro generates **fresh for every build**:
///   a randomized, straight-line sequence of invertible byte operations
///   (XORs, additions, rotations, permutations, reversals) over scattered
///   key shares, different on each compile. [`decrypt`](EncryptedFile::decrypt)
///   / [`decrypt_str`](EncryptedFile::decrypt_str) call it to recover the
///   key; both are infallible by construction. This is
///   **obfuscation, not security**: the key ships inside the binary, and
///   anyone with the binary (a reverser, a disassembler, a memory dump) can
///   recover it and decrypt the payload. The per-build randomization only
///   raises the bar against casual static extraction — grepping the binary
///   for plaintext strings, or writing one generic extractor that works on
///   every `embark` binary — not against a determined attacker willing to
///   reverse an individual binary.
/// - **`EncryptedFile<RuntimeKey>`** (opt in with
///   `embed_crypt!(..., key = runtime)`) — built with
///   [`with_runtime_key`](EncryptedFile::with_runtime_key). No key is ever
///   embedded in the binary; the caller supplies the key at runtime via
///   [`decrypt_with`](EncryptedFile::decrypt_with), giving real
///   confidentiality (as strong as the caller's own key management).
///   There is no `decrypt()` on this mode: there is no embedded key to
///   decrypt with, so the method simply does not exist for this type
///   rather than failing at runtime. The handle stores nothing but the
///   sealed entry — the mode's [`KeySource`](KeyMode::KeySource) is `()`,
///   so there is no field key material could occupy.
///
/// Use the build-time mode for casual tamper-resistance (e.g. keeping a
/// default config out of a quick `strings` scan); use the runtime-key mode
/// whenever the embedded content actually needs to stay confidential.
///
/// # Examples
///
/// Build-time embedded key (the default). Note the plain `EncryptedFile`
/// type and the infallible `decrypt`:
///
/// ```
/// # #[cfg(all(feature = "derive", feature = "std"))] {
/// static SECRET: embark::EncryptedFile =
///     embark::embed_crypt!("examples/assets/secret.txt");
///
/// assert!(SECRET.decrypt_str().unwrap().starts_with("the launch codes"));
/// assert_eq!(SECRET.decrypt(), SECRET.decrypt_str().unwrap().as_bytes());
/// # }
/// ```
///
/// `embed_crypt!` takes `codec` and `cipher` as **bare identifiers**, never
/// as strings. (The `#[derive(Embed)]` attribute is the opposite: it takes
/// the string forms, shown below.)
///
/// ```
/// # #[cfg(all(feature = "derive", feature = "std"))] {
/// static SEALED: embark::EncryptedFile = embark::embed_crypt!(
///     "examples/assets/secret.txt",
///     codec = deflate,
///     cipher = chacha
/// );
/// assert!(SEALED.decrypt_str().unwrap().starts_with("the launch codes"));
///
/// // `cipher = aes` requires embark's `aes` feature; naming it without
/// // that feature is a build error, not a silent fallback.
/// # #[cfg(feature = "aes")] {
/// static AES: embark::EncryptedFile =
///     embark::embed_crypt!("examples/assets/secret.txt", cipher = aes);
/// assert_eq!(AES.decrypt(), SEALED.decrypt());
/// # }
/// # }
/// ```
///
/// The derive spells the same choices as strings, and seals every file in
/// the folder under one shared build-time key:
///
/// ```
/// # #[cfg(all(feature = "derive", feature = "std"))] {
/// use embark::Embed as _;
///
/// #[derive(embark::Embed)]
/// #[embark(folder = "examples/assets/docs", encrypt, cipher = "chacha")]
/// struct Secrets;
///
/// assert!(Secrets::get("license.txt").unwrap().data().starts_with(b"MIT"));
/// # }
/// ```
///
/// Runtime key. The binding must be explicitly typed
/// `EncryptedFile<RuntimeKey>`, and `decrypt_with` is the only way to open
/// it. This one is not run as a doctest: `key = runtime` reads the key from
/// the `EMBARK_KEY` environment variable at *build* time, so it cannot be
/// expanded from within a test that does not control the compiler's
/// environment.
///
/// ```ignore
/// // Built with EMBARK_KEY=<64 hex chars> in the environment.
/// static SEALED: embark::EncryptedFile<embark::RuntimeKey> =
///     embark::embed_crypt!("examples/assets/secret.txt", key = runtime);
///
/// let key: [u8; 32] = load_key_from_somewhere();
/// let plaintext = SEALED.decrypt_with(&key).unwrap();
/// ```
pub struct EncryptedFile<K: KeyMode = EmbeddedKey> {
    entry: &'static [u8],
    // Whatever the mode needs to open the entry, and nothing more: the
    // per-build-randomized key-reconstruction function for `EmbeddedKey`,
    // `()` for `RuntimeKey`. A runtime-key handle therefore has no field a
    // key could be parked in, not even a zeroed placeholder.
    key: K::KeySource,
}

impl EncryptedFile<EmbeddedKey> {
    /// Builds a build-time-embedded-key handle from a sealed entry and its
    /// key-reconstruction function.
    ///
    /// This is normally emitted by the `embed_crypt!` macro or the
    /// `#[derive(Embed)]` `#[embark(encrypt)]` attribute, not called
    /// directly. `recon` is a per-build-randomized function the macro
    /// generates that rebuilds the embedded key when called; it is invoked at
    /// decrypt time. See the [type-level docs](EncryptedFile) for why this is
    /// obfuscation, not encryption in the security sense.
    pub const fn with_embedded_key(
        entry: &'static [u8],
        recon: fn() -> [u8; 32],
    ) -> EncryptedFile<EmbeddedKey> {
        EncryptedFile { entry, key: recon }
    }

    /// Decrypts using the build-time embedded key.
    ///
    /// Infallible by construction: this method only exists on
    /// `EncryptedFile<EmbeddedKey>`, whose key is always baked in, so
    /// decryption cannot fail short of build-time corruption of the
    /// compiled-in entry.
    ///
    /// Remember: even when it succeeds, this mode is
    /// **obfuscation, not security** — see the [type-level docs](EncryptedFile).
    ///
    /// # Panics
    ///
    /// Panics only if the embedded entry is malformed -- a build-time bug,
    /// not something a caller can trigger at runtime.
    pub fn decrypt(&self) -> Vec<u8> {
        let key = (self.key)();
        crate::decode::decode(self.entry, Some(key))
            .expect("embark: embedded entry is malformed (this is a build-time bug)")
            .into_owned()
    }

    /// Like [`decrypt`](EncryptedFile::decrypt), but decodes the result as
    /// UTF-8 and returns a `Result` (rather than panicking) if the
    /// decrypted bytes are not valid UTF-8.
    pub fn decrypt_str(&self) -> Result<String, Error> {
        let key = (self.key)();
        let bytes = crate::decode::decode(self.entry, Some(key))?.into_owned();
        String::from_utf8(bytes).map_err(|_| Error::Utf8)
    }
}

impl EncryptedFile<RuntimeKey> {
    /// Builds a runtime-key handle: the sealed entry, with no key material
    /// embedded in the binary.
    ///
    /// Decrypt it with [`decrypt_with`](EncryptedFile::decrypt_with),
    /// supplying the key yourself. There is no `decrypt()` on this type --
    /// calling it is a compile error, not a runtime panic:
    ///
    /// ```compile_fail
    /// let f: embark::EncryptedFile<embark::RuntimeKey> =
    ///     embark::EncryptedFile::with_runtime_key(&[]);
    /// f.decrypt(); // error[E0599]: no method named `decrypt` found
    /// ```
    pub const fn with_runtime_key(entry: &'static [u8]) -> EncryptedFile<RuntimeKey> {
        EncryptedFile { entry, key: () }
    }

    /// Decrypts with a caller-supplied key, never relying on any key
    /// embedded in the binary.
    ///
    /// This is the only way to decrypt a runtime-key handle -- real
    /// confidentiality, as strong as the caller's own key management.
    /// Returns `Err(Error::Auth)` if `key` is wrong (AEAD authentication
    /// fails cleanly rather than returning garbage).
    pub fn decrypt_with(&self, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        Ok(crate::decode::decode(self.entry, Some(*key))?.into_owned())
    }
}
