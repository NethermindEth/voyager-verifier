# Integrating Voyager Verification in `sncast`

This guide describes how `starknet-foundry` can use the `voyager-verifier`
library from `sncast` without copying Voyager request-building logic.

## Dependency

For local development in `starknet-foundry`, add the library to
`crates/sncast/Cargo.toml`:

```toml
voyager-verifier = { version = "2.3.0", path = "../../../voyager-verifier/crates/voyager-verifier", default-features = false }
```

After `voyager-verifier` `2.3.0` is published to crates.io, remove the local
`path`:

```toml
voyager-verifier = { version = "2.3.0", default-features = false }
```

## Imports

In the `sncast` Voyager verifier module, import the reusable library API:

```rust
use voyager_verifier::{
    core::project::ProjectType,
    voyager::{
        collect_verification_files, prepare_verification_request, select_package,
        submit_verification_request, MAINNET_API_URL, SEPOLIA_API_URL, STATUS_ENDPOINT,
    },
};
```

## Suggested Flow

Keep `sncast` responsible for Starknet Foundry concerns:

- resolving a contract address to a class hash;
- choosing the network or explorer URL;
- prompting for confirmation;
- formatting the final `VerifyResponse`;
- returning the existing unsupported-devnet behavior.

Use `voyager-verifier` for Voyager-specific work:

```rust
let prepared = prepare_verification_request(
    &metadata,
    &contract_name,
    package.as_deref(),
    include_test_files,
    ProjectType::Scarb,
    None,
)?;
```

Then submit the prepared request:

```rust
let api_base_url = Url::parse(match network {
    Network::Mainnet => MAINNET_API_URL,
    Network::Sepolia => SEPOLIA_API_URL,
})?;

let job_id = submit_verification_request(
    &api_base_url,
    &format!("{class_hash:#066x}"),
    &prepared.request,
)
.await?;
```

Build the status URL in `sncast` from the returned job ID:

```rust
let status_url = format!(
    "{}/{}/{}",
    explorer_url.trim_end_matches('/'),
    STATUS_ENDPOINT,
    job_id,
);
```

If `sncast` needs to display the files before asking for confirmation, call:

```rust
let files = collect_verification_files(&metadata, include_test_files)?;
```

If `sncast` needs to validate or display the selected workspace package before
building the request, call:

```rust
let package = select_package(&metadata, package.as_deref())?;
```

## Dojo Support

Current `sncast` Voyager verification should use:

```rust
ProjectType::Scarb
```

If `sncast` later supports Dojo verification through Voyager, pass:

```rust
ProjectType::Dojo
```

and provide the detected Dojo version as the final
`prepare_verification_request` argument.

## Checks

From `starknet-foundry`, run:

```sh
cargo check -p sncast
```

If the local devnet test harness is available, also run:

```sh
cargo test -p sncast --test main verify::voyager -- --nocapture
```
