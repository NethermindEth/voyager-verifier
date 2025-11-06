# Desktop Notifications

Desktop notifications alert you when verification completes, allowing you to continue working while the verification runs in the background.

## Overview

Desktop notifications provide:

- **Automatic alerts** when verification completes
- **Status indication** - Success ✅ or Failure ❌
- **Non-intrusive** - Only appears on completion
- **Cross-platform** - Works on Linux, macOS, and Windows
- **Optional feature** - Can be disabled during build

## Requirements

### Watch Mode Required

Desktop notifications **require watch mode** to be enabled:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --watch \
  --notify
```

Without `--watch`, the `--notify` flag has no effect because the tool exits immediately after submission.

### Platform Requirements

#### Linux

**Requirements:**
- D-Bus service running
- Notification daemon (e.g., `notify-send`, GNOME Shell, KDE Plasma)

**Verify setup:**
```bash
# Test with notify-send
notify-send "Test" "Notification working"
```

**Common notification daemons:**
- GNOME Shell (GNOME desktop)
- KDE Plasma (KDE desktop)
- dunst (lightweight daemon)
- mako (Wayland compositor)

#### macOS

**Requirements:**
- macOS 10.14 (Mojave) or later
- No additional setup needed

**Behavior:**
- Uses native macOS notification system
- Appears in Notification Center
- Works out of the box

#### Windows

**Requirements:**
- Windows 10 or Windows 11
- No additional setup needed

**Behavior:**
- Uses Windows notification system
- Appears in Action Center
- Works out of the box

## Usage

### Basic Usage

Enable notifications with watch mode:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --watch \
  --notify
```

**Workflow:**
1. Submit verification
2. Watch mode monitors progress
3. Notification appears when complete
4. Continue working on other tasks

### In Configuration File

Set as default in `.voyager.toml`:

```toml
[voyager]
watch = true
notify = true
```

**Then run:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken
```

### With Interactive Wizard

The wizard prompts for notification preference:

```
Monitor verification status until completion? [Y/n]: y
Enable desktop notifications? [y/N]: y
```

### With Batch Verification

Enable for all contracts in a batch:

```bash
voyager verify --watch --notify
```

All contract verifications in the batch will trigger notifications.

## Notification Content

### Success Notification

**Title:** `✅ Verification Successful`

**Body:**
```
Contract: MyToken
Class Hash: 0x044dc2b3...da18
Network: mainnet
```

**Example:**
```
┌─────────────────────────────────────┐
│ ✅ Verification Successful          │
│                                     │
│ Contract: MyToken                   │
│ Class Hash: 0x044dc2b3...da18      │
│ Network: mainnet                    │
└─────────────────────────────────────┘
```

### Failure Notification

**Title:** `❌ Verification Failed`

**Body:**
```
Contract: MyToken
Class Hash: 0x044dc2b3...da18
Network: mainnet
Status: CompileFailed
```

**Example:**
```
┌─────────────────────────────────────┐
│ ❌ Verification Failed              │
│                                     │
│ Contract: MyToken                   │
│ Class Hash: 0x044dc2b3...da18      │
│ Network: mainnet                    │
│ Status: CompileFailed               │
└─────────────────────────────────────┘
```

### Notification Timing

Notifications appear only for **terminal states**:

- ✅ **Success** - Verification successful
- ❌ **Failed** - Verification failed (mismatch)
- ❌ **CompileFailed** - Compilation failed

**No notifications** for intermediate states (Submitted, Compiling, etc.).

## Configuration

### Priority Order

Notification setting can be specified in multiple ways:

1. **CLI flag** (highest priority)
   ```bash
   voyager verify --watch --notify
   ```

2. **Configuration file**
   ```toml
   [voyager]
   notify = true
   ```

3. **Default** (lowest priority)
   - Default: `false` (disabled)

### Enabling by Default

Set in `.voyager.toml`:

```toml
[voyager]
watch = true
notify = true
```

**All verification commands will now send notifications by default.**

### Disabling Temporarily

Override config file for a single command:

```bash
# Config has notify = true, but disable for this run
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --watch
  # Omit --notify to disable
```

## Use Cases

### Long-Running Verifications

For contracts that take several minutes to verify:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --watch \
  --notify
```

**Benefit:** Work on other tasks, get notified when complete.

### Batch Verifications

Monitor multiple verifications:

```bash
voyager verify --watch --notify
```

**Behavior:** Notification appears when **all** verifications complete.

### Development Workflow

Typical development cycle:

```bash
# Deploy contract
starkli declare ...
starkli deploy ...

# Submit verification with notification
voyager verify --network sepolia \
  --class-hash <HASH> \
  --contract-name MyContract \
  --watch \
  --notify

# Continue coding while verification runs
# Notification alerts when complete
```

### Background Verification

Run in a separate terminal:

```bash
# Terminal 1: Verification with notifications
voyager verify --watch --notify

# Terminal 2: Continue development
vim src/contract.cairo
scarb build
scarb test
```

## Building Without Notifications

### Disable Feature During Build

If you don't want notification support:

```bash
cargo build --release --no-default-features
```

or

```bash
cargo install voyager-verifier --no-default-features
```

**Effect:**
- Reduces dependencies
- Smaller binary size
- `--notify` flag will not be available

### Check If Notifications Are Enabled

Run `voyager --help` and check for `--notify`:

**With notifications:**
```bash
voyager verify --help | grep notify
  --notify    Send desktop notifications when verification completes
```

**Without notifications:**
```bash
voyager verify --help | grep notify
  # No output - flag not available
```

## Troubleshooting

### Notifications Not Appearing

#### On Linux

**Check D-Bus:**
```bash
# Verify D-Bus is running
ps aux | grep dbus

# Test with notify-send
notify-send "Test" "Hello"
```

**Install notification daemon:**

Ubuntu/Debian:
```bash
sudo apt-get install libnotify-bin
```

Arch:
```bash
sudo pacman -S libnotify
```

Fedora:
```bash
sudo dnf install libnotify
```

**Check desktop environment:**
- Ensure your desktop environment has a notification daemon
- Some minimal window managers require manual setup

#### On macOS

**Check Notification Center settings:**
1. System Preferences → Notifications
2. Ensure notifications are enabled
3. Check "Do Not Disturb" is not active

**Terminal permissions:**
- macOS may require Terminal.app to have notification permissions
- System Preferences → Notifications → Terminal

#### On Windows

**Check Windows settings:**
1. Settings → System → Notifications & actions
2. Ensure notifications are enabled
3. Check "Focus assist" settings

### "notify" Flag Not Recognized

**Cause:** Built without notifications feature

**Solution:**
```bash
# Rebuild with notifications
cargo build --release

# Or reinstall with default features
cargo install voyager-verifier
```

### Notification Appears But No Content

**Cause:** Platform-specific formatting issue

**Workaround:** Check terminal output for verification result

**Report:** File an issue with platform details

### Watch Mode Required Error

```
Error: --notify requires --watch to be enabled
```

**Solution:** Add `--watch` flag:

```bash
voyager verify --watch --notify
```

## Platform-Specific Notes

### Linux

- Works with X11 and Wayland
- Requires D-Bus
- Notification daemon must be running
- Some window managers need manual configuration

**Testing:**
```bash
# Install notification tools
sudo apt-get install libnotify-bin

# Test notification
notify-send "Voyager Test" "Notifications working"
```

### macOS

- Uses NSUserNotificationCenter
- Works on macOS 10.14+
- Appears in Notification Center
- Terminal.app may need notification permissions

**Granting permissions:**
1. System Preferences → Security & Privacy → Privacy
2. Select "Notifications" from the left sidebar
3. Enable Terminal.app

### Windows

- Uses Windows Toast notifications
- Works on Windows 10/11
- Appears in Action Center
- No special configuration needed

## Best Practices

### 1. Use for Long Verifications

Enable notifications when verification takes >1 minute:

```bash
voyager verify --watch --notify
```

### 2. Disable in CI/CD

Don't use notifications in automated environments:

```toml
# .voyager.toml for CI
[voyager]
watch = false
notify = false
```

### 3. Set as Default Locally

For local development, enable by default:

```toml
# .voyager.toml
[voyager]
watch = true
notify = true
```

### 4. Test Notification Setup

Verify notifications work before relying on them:

```bash
# On Linux
notify-send "Test" "Notification check"

# With voyager (quick verification)
voyager verify --network sepolia \
  --class-hash <TEST_HASH> \
  --contract-name Test \
  --watch \
  --notify
```

### 5. Combine with Background Execution

Run verification in background terminal:

```bash
# Terminal 1
voyager verify --watch --notify

# Terminal 2
# Continue working
```

## Security Considerations

### No Sensitive Data in Notifications

Notifications display:
- ✅ Contract name (safe - user-provided)
- ✅ Shortened class hash (safe - public blockchain data)
- ✅ Network (safe - public information)
- ✅ Status (safe - success/fail)

**No sensitive information** is included in notifications.

### Notification Permissions

Notifications use standard OS APIs:
- No special permissions required (except on macOS)
- Cannot access other apps' data
- Cannot perform privileged operations

## See Also

- [Watch Mode](../verification/watch-mode.md) - Watch mode documentation
- [verify command](../commands/verify.md) - verify command reference
- [Configuration file](../configuration/config-file.md) - Configuration options
- [Batch Verification](../verification/batch-verification.md) - Batch notifications