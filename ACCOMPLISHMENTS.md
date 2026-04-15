# Voyager Verifier Library Extraction

## Summary

Extracted the Voyager verification logic used by `sncast` into the `voyager-verifier` crate so it can be published to crates.io and consumed as a reusable library.

## Changes in `voyager-verifier`

- Added a new public `voyager_verifier::voyager` module in `crates/voyager-verifier/src/voyager.rs`.
- Added reusable helpers for:
  - collecting Voyager verification files from Scarb metadata;
  - selecting a target workspace package;
  - preparing the Voyager verification request payload;
  - submitting verification requests asynchronously;
  - building Voyager verification URLs;
  - filtering `[dev-dependencies]` from uploaded `Scarb.toml` files.
- Re-exported `VerificationRequest` from `voyager_verifier::api`.
- Exposed the new `voyager` module from `crates/voyager-verifier/src/lib.rs`.
- Bumped the crate version from `2.2.0` to `2.3.0` because `2.2.0` is already published on crates.io.
- Added `build.rs` to the package include list so `cargo package` verifies successfully with the default macOS notifications feature.
- Split the repository into a Cargo workspace with:
  - `crates/voyager-verifier` for the reusable library published to crates.io;
  - `crates/voyager` for the standalone CLI binary used by GitHub release artifacts and asdf.

## Changes in `starknet-foundry`

- Added `voyager-verifier` as a dependency of `sncast`.
- Replaced the copied Voyager verification implementation in `crates/sncast/src/starknet_commands/verify/voyager.rs` with calls into `voyager_verifier::voyager`.
- Kept the local path dependency for development:

```toml
voyager-verifier = { version = "2.3.0", path = "../../../voyager-verifier/crates/voyager-verifier", default-features = false }
```

After `voyager-verifier` `2.3.0` is published, `sncast` can remove the `path` field and depend on the crates.io version.

## Verification Performed

- `cargo check` in `voyager-verifier`: passed.
- `cargo test` in `voyager-verifier`: passed.
- `cargo package --allow-dirty` in `voyager-verifier`: passed.
- `cargo check -p sncast` in `starknet-foundry`: passed.
- `cargo test -p sncast --test main verify::voyager -- --nocapture`: compiled the test target, then failed before running the filtered tests because the harness timed out waiting for devnet.

## Publishing Note

The crate is packaged and ready for publishing as `voyager-verifier` `2.3.0`, but `cargo publish` was not run because publishing requires crates.io credentials and is irreversible.

## How To Integrate With `sncast`

### 1. Add the dependency

While developing locally, add the dependency to `crates/sncast/Cargo.toml` with both `version` and `path`:

```toml
voyager-verifier = { version = "2.3.0", path = "../../../voyager-verifier/crates/voyager-verifier", default-features = false }
```

After `voyager-verifier` `2.3.0` is published to crates.io, remove the `path` field:

```toml
voyager-verifier = { version = "2.3.0", default-features = false }
```

`default-features = false` is recommended for `sncast` because it only needs the reusable verification library code, not the Voyager CLI desktop notification feature.

### 2. Import the reusable Voyager API

In `crates/sncast/src/starknet_commands/verify/voyager.rs`, import the helpers from the library:

```rust
use voyager_verifier::{
    core::project::ProjectType,
    voyager::{
        MAINNET_API_URL, SEPOLIA_API_URL, STATUS_ENDPOINT, collect_verification_files,
        prepare_verification_request, select_package, submit_verification_request,
    },
};
```

### 3. Replace local file collection

Replace the copied local implementations of package gathering, source file discovery, and common-prefix calculation with:

```rust
let files = collect_verification_files(&self.metadata, include_test_files)?;
Ok((files.prefix, files.files))
```

This preserves the existing `sncast` display flow, where `sncast` gathers file names before asking the user for confirmation.

### 4. Replace local request body construction

After resolving the class hash and checking the selected package license, prepare the Voyager request through the library:

```rust
let prepared = prepare_verification_request(
    &self.metadata,
    &contract_name,
    package.as_deref(),
    test_files,
    ProjectType::Scarb,
    None,
)?;
```

For current `sncast` Voyager verification, `ProjectType::Scarb` and `None` for `dojo_version` match the existing behavior. If `sncast` later supports Dojo verification through Voyager, pass `ProjectType::Dojo` and the detected Dojo version.

### 5. Submit through the library

Build the base URL using the existing `sncast` network/environment logic, then submit:

```rust
let api_base_url = Url::parse(&self.gen_explorer_url()?)?;
let job_id =
    submit_verification_request(&api_base_url, &format!("{hash:#066x}"), &prepared.request)
        .await?;
```

Then build the existing `VerifyResponse` message from the returned `job_id`:

```rust
let status_url = format!(
    "{}/{}/{}",
    self.gen_explorer_url()?.trim_end_matches('/'),
    STATUS_ENDPOINT,
    job_id,
);
let message = format!(
    "{contract_name} submitted for verification, you can query the status at: {status_url}"
);
```

### 6. Keep `sncast`-specific behavior in `sncast`

The library intentionally does not own `sncast` concerns such as:

- resolving a contract address to a class hash through the Starknet provider;
- printing UI warnings;
- prompting for user confirmation;
- formatting `VerifyResponse`;
- choosing `Network::Mainnet`, `Network::Sepolia`, or returning the existing devnet unsupported error.

Those pieces should remain in `sncast`; only Voyager payload preparation, file collection, package selection, URL constants, and request submission should come from `voyager-verifier`.

### 7. Verify the integration

Run:

```sh
cargo check -p sncast
```

If the local devnet test harness is available, also run:

```sh
cargo test -p sncast --test main verify::voyager -- --nocapture
```

During this extraction, `cargo check -p sncast` passed. The filtered Voyager e2e test target compiled, but the harness timed out waiting for devnet before running the filtered tests.
