build-darwin:
	cargo build --package voyager --release --target aarch64-apple-darwin
	cargo build --package voyager --release --target x86_64-apple-darwin

build-linux:
	cargo build --package voyager --release --target x86_64-unknown-linux-gnu

build-windows:
	cargo build --package voyager --release --target x86_64-pc-windows-gnu
