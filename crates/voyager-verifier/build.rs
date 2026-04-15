fn main() {
    // Link macOS frameworks required by notify-rust when notifications feature is enabled
    #[cfg(all(target_os = "macos", feature = "notifications"))]
    {
        println!("cargo:rustc-link-lib=framework=AppKit");
        println!("cargo:rustc-link-lib=framework=CoreServices");
    }
}
