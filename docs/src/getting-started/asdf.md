# Installation with asdf

asdf is a version manager that allows you to install and manage multiple versions of voyager-verifier (and many other tools) on your system.

## Prerequisites

First, you'll need to install asdf if you haven't already. Follow the official [asdf installation guide](https://asdf-vm.com/guide/getting-started.html).

## Installation Steps

### 1. Add the Voyager Plugin

Add the voyager-verifier plugin to asdf:

```bash
asdf plugin add voyager https://github.com/NethermindEth/asdf-voyager-verifier.git
```

### 2. Install the Latest Version

Install the latest version of voyager-verifier:

```bash
asdf install voyager latest
```

This will download and install the most recent version available.

### 3. Set Global Version

Set the installed version as your global default:

```bash
asdf global voyager latest
```

Alternatively, set it for the current directory only:

```bash
asdf local voyager latest
```

### 4. Verify Installation

Confirm the installation was successful:

```bash
voyager --version
```

You should see output like:

```
voyager-verifier 2.0.0-alpha.5
```

## Managing Versions

### List Available Versions

See all available versions:

```bash
asdf list all voyager
```

### Install Specific Version

Install a specific version:

```bash
asdf install voyager 1.3.0
```

### Switch Versions

Switch to a different installed version globally:

```bash
asdf global voyager 1.3.0
```

Or for the current directory:

```bash
asdf local voyager 1.3.0
```

### List Installed Versions

See which versions you have installed:

```bash
asdf list voyager
```

## Updating

### Update to Latest Version

To update to the latest version:

```bash
asdf install voyager latest
asdf global voyager latest
```

### Update the Plugin

To get access to newly released versions, update the plugin:

```bash
asdf plugin update voyager
```

## Uninstalling

### Remove a Specific Version

```bash
asdf uninstall voyager 1.3.0
```

### Remove the Plugin

To completely remove voyager-verifier from asdf:

```bash
asdf plugin remove voyager
```

## Project-Specific Versions

For project-specific version management, create a `.tool-versions` file in your project directory:

```bash
echo "voyager 2.0.0-alpha.5" > .tool-versions
```

When you `cd` into this directory, asdf will automatically use the specified version.

## Troubleshooting

### Command Not Found

If `voyager` command is not found after installation:

1. Make sure asdf is properly configured in your shell profile (`.bashrc`, `.zshrc`, etc.)
2. Restart your terminal or run `source ~/.bashrc` (or your shell's config file)
3. Verify asdf is working: `asdf --version`

### Plugin Installation Fails

If adding the plugin fails:

1. Ensure you have git installed
2. Check your network connection
3. Verify the plugin URL is correct

### Version Not Available

If a specific version isn't available:

```bash
# Update the plugin to fetch latest versions
asdf plugin update voyager

# List available versions again
asdf list all voyager
```

## Next Steps

Now that voyager-verifier is installed, proceed to the [Quickstart Guide](./quickstart.md) to verify your first contract!
