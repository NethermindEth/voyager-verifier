# Dojo Project Example

This example walks through verifying a Dojo project that includes models and systems. Dojo is a provable game engine built on Starknet, and verifying Dojo contracts requires special handling that voyager-verifier automatically detects and manages.

## Overview

You'll learn how to:
- Set up a Dojo project with models and systems
- Configure Scarb.toml with Dojo-specific settings
- Understand key differences from standard Scarb projects
- Verify Dojo contracts using voyager-verifier
- Handle Dojo world contracts and dependencies
- Troubleshoot Dojo-specific issues

**Time Required:** 20-25 minutes

**Difficulty:** Intermediate

## What is Dojo?

[Dojo](https://book.dojoengine.org) is a provable game engine built on Starknet. It provides:
- **Entity Component System (ECS)** - Efficient game state management
- **Models** - On-chain data structures with `#[dojo::model]` decorator
- **Systems** - Game logic contracts with `#[dojo::contract]` decorator
- **World Contract** - Central registry connecting models and systems
- **Sozo** - Dojo's build and deployment tool

### How Verification Works with Dojo

Voyager-verifier automatically detects Dojo projects by checking for:
1. `dojo` dependency in `Scarb.toml`
2. Dojo-specific imports (`use dojo::...`)
3. Dojo decorators (`#[dojo::model]`, `#[dojo::contract]`)

When detected, it uses `sozo build` instead of `scarb build` to ensure proper compilation.

## Project Structure

We'll create a simple game with player movement:

```
dojo-game/
├── Scarb.toml                # Dojo project configuration
├── Scarb.lock                # Dependency lock file
├── .voyager.toml             # Optional: Verification config
├── dojo_dev.toml             # Dojo development config
├── manifest_dev.json         # Dojo deployment manifest
└── src/
    ├── lib.cairo             # Module declarations
    ├── models.cairo          # Game models (Position, Moves)
    └── systems/
        └── actions.cairo     # Game systems (spawn, move)
```

## Key Differences from Standard Scarb

### 1. Cairo Version Specification

Dojo projects must specify an exact Cairo version:

```toml
[package]
cairo-version = "2.12.2"  # Required for Dojo
```

### 2. Sierra Replace IDs

Dojo requires this setting for deterministic builds:

```toml
[cairo]
sierra-replace-ids = true  # Required for Dojo
```

### 3. Dojo Dependencies

Use the `dojo` dependency instead of individual Dojo packages:

```toml
[dependencies]
starknet = "2.12.2"
dojo = "1.7.2"  # Single unified dependency
```

### 4. World Contract Build

Dojo projects must build the world contract:

```toml
[[target.starknet-contract]]
build-external-contracts = ["dojo::world::world_contract::world"]
```

### 5. Dojo Macros and Decorators

Models and contracts use special Dojo decorators:

```cairo
#[dojo::model]  // Marks a struct as a Dojo model
pub struct Position { ... }

#[dojo::contract]  // Marks a module as a Dojo system
pub mod actions { ... }
```

## Step 1: Create the Project

Initialize a new Dojo project:

```bash
# Using Dojo's project initializer
sozo init dojo-game
cd dojo-game

# Or create manually:
mkdir dojo-game
cd dojo-game
```

## Step 2: Configure Scarb.toml

Create or update `Scarb.toml` with Dojo-specific configuration:

```toml
[package]
cairo-version = "2.12.2"
name = "dojo_game"
version = "1.7.2"
edition = "2024_07"
license = "MIT"

[cairo]
sierra-replace-ids = true

[dependencies]
starknet = "2.12.2"
dojo = "1.7.2"

[tool.scarb]
allow-prebuilt-plugins = ["dojo_cairo_macros"]

[[target.starknet-contract]]
build-external-contracts = ["dojo::world::world_contract::world"]

[dev-dependencies]
cairo_test = "2.12.2"
dojo_cairo_test = "1.7.2"
```

**Critical Settings:**
- `cairo-version` - Must match your Dojo version's Cairo requirement
- `sierra-replace-ids = true` - Required for deterministic builds
- `dojo` dependency - Version should match your Dojo installation
- `build-external-contracts` - Ensures world contract is built

## Step 3: Create the Module Structure

Create `src/lib.cairo` to declare modules:

```cairo
pub mod models;
pub mod systems {
    pub mod actions;
}
```

This organizes your models and systems into separate files.

## Step 4: Create Game Models

Create `src/models.cairo` with your game data structures:

```cairo
use starknet::ContractAddress;
use core::num::traits::{SaturatingAdd, SaturatingSub};

/// Direction enum for player movement
#[derive(Serde, Copy, Drop, Default, Introspect)]
pub enum Direction {
    #[default]
    Left,    // Serialized as 0
    Right,   // Serialized as 1
    Up,      // Serialized as 2
    Down,    // Serialized as 3
}

/// Player position on the game board
#[derive(Copy, Drop, Serde)]
#[dojo::model]
pub struct Position {
    #[key]
    pub player: ContractAddress,
    pub x: u32,
    pub y: u32,
}

/// Remaining moves for a player
#[derive(Copy, Drop, Serde)]
#[dojo::model]
pub struct Moves {
    #[key]
    pub player: ContractAddress,
    pub remaining: u8,
}

/// Implementation for applying direction to position
#[generate_trait]
pub impl PositionImpl of PositionTrait {
    fn apply_direction(ref self: Position, direction: Direction) {
        match direction {
            Direction::Left => { self.x = self.x.saturating_sub(1) },
            Direction::Right => { self.x = self.x.saturating_add(1) },
            Direction::Up => { self.y = self.y.saturating_add(1) },
            Direction::Down => { self.y = self.y.saturating_sub(1) },
        }
    }
}
```

**Key Points:**
- `#[dojo::model]` - Registers struct as a Dojo model
- `#[key]` - Marks the field used for indexing
- `Introspect` - Required derive for Dojo models

## Step 5: Create Game Systems

Create `src/systems/actions.cairo` with game logic:

```cairo
use crate::models::Direction;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IActions<T> {
    fn spawn(ref self: T);
    fn move(ref self: T, direction: Direction);
}

#[dojo::contract]
pub mod actions {
    use super::IActions;
    use crate::models::{Direction, Moves, Position, PositionTrait};
    use core::num::traits::SaturatingSub;
    use dojo::model::ModelStorage;

    pub const INIT_COORD: u32 = 10;
    pub const INIT_REMAINING_MOVES: u8 = 100;

    #[abi(embed_v0)]
    impl ActionsImpl of IActions<ContractState> {
        fn spawn(ref self: ContractState) {
            let mut world = self.world_default();
            let player = starknet::get_caller_address();

            // Create initial position
            let position = Position {
                player,
                x: INIT_COORD,
                y: INIT_COORD,
            };

            // Create initial moves
            let moves = Moves {
                player,
                remaining: INIT_REMAINING_MOVES,
            };

            // Write to world state
            world.write_model(@position);
            world.write_model(@moves);
        }

        fn move(ref self: ContractState, direction: Direction) {
            let mut world = self.world_default();
            let player = starknet::get_caller_address();

            // Update position
            let mut position: Position = world.read_model(player);
            position.apply_direction(direction);
            world.write_model(@position);

            // Decrement moves
            let mut moves: Moves = world.read_model(player);
            moves.remaining = moves.remaining.saturating_sub(1);
            world.write_model(@moves);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn world_default(self: @ContractState) -> dojo::world::WorldStorage {
            self.world(@"di")
        }
    }
}
```

**Key Points:**
- `#[dojo::contract]` - Registers module as a Dojo system
- `world.read_model()` / `write_model()` - Access Dojo world state
- `ModelStorage` - Dojo's storage interface

## Step 6: Build with Dojo

Build your Dojo project using sozo:

```bash
sozo build
```

**Expected Output:**
```
   Compiling dojo_game v1.7.2 (~/dojo-game/Scarb.toml)
   Compiling dojo::world::world_contract v1.7.2
    Finished release target(s) in 5 seconds
```

Dojo builds both your contracts and the world contract.

## Step 7: Deploy to Starknet

Deploy your Dojo world to get the contract class hashes:

```bash
# Initialize Dojo world on Sepolia testnet
sozo build
sozo migrate --network sepolia

# This creates manifest_dev.json with deployed addresses
```

The manifest file contains class hashes for:
- **World contract** - The central world registry
- **Models** - Position, Moves
- **Systems** - actions (spawn, move)

**Example Class Hashes:**
```
actions contract: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
Position model:   0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19
Moves model:      0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20
World contract:   0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21
```

## Step 8: Verify Dojo Contracts

Now verify your deployed contracts using voyager-verifier.

### Method 1: Automatic Detection (Recommended)

Voyager automatically detects Dojo projects:

```bash
voyager verify \
    --network sepolia \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name actions \
    --watch
```

**Detection Process:**
```
✓ Detected Dojo project (dojo = "1.7.2")
✓ Using sozo build tool
✓ Files collected: 3 files
  - src/lib.cairo
  - src/models.cairo
  - src/systems/actions.cairo
```

### Method 2: Explicit Dojo Type

Explicitly specify Dojo project type:

```bash
voyager verify \
    --network sepolia \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name actions \
    --project-type dojo \
    --watch
```

### Method 3: Interactive Mode

Use the wizard for guided verification:

```bash
voyager verify --wizard
```

Select "Dojo project" when prompted for project type.

### Method 4: Configuration File

Create `.voyager.toml` for repeated verifications:

```toml
[voyager]
network = "sepolia"
license = "MIT"
watch = true
project-type = "dojo"  # Explicitly set Dojo type

# Verify the actions system
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "actions"
```

Then run:

```bash
voyager verify
```

## Step 9: Verify Multiple Dojo Contracts

Verify all contracts from your Dojo world at once:

### Using Batch Configuration

Create `.voyager.toml`:

```toml
[voyager]
network = "sepolia"
license = "MIT"
watch = true
project-type = "dojo"

# Actions system
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "actions"

# Position model contract
[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "Position"

# Moves model contract
[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "Moves"
```

Run batch verification:

```bash
voyager verify
```

**Expected Output:**
```
[1/3] Verifying: actions
  ✓ Detected Dojo project (dojo = "1.7.2")
  ✓ Submitted - Job ID: abc-123-def

[2/3] Verifying: Position
  ✓ Using cached build
  ✓ Submitted - Job ID: ghi-456-jkl

[3/3] Verifying: Moves
  ✓ Using cached build
  ✓ Submitted - Job ID: mno-789-pqr

════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  3
Submitted:        3
Succeeded:        0
Failed:           0
Pending:          3
════════════════════════════════════════

⏳ Watching verification jobs...

✓ All verifications completed successfully!
```

## Expected Output

### Successful Dojo Verification

```
✓ Detected Dojo project automatically
  Dojo version: 1.7.2
  Cairo version: 2.12.2
  Build tool: sozo

✓ Files collected: 3 files
  - src/lib.cairo
  - src/models.cairo
  - src/systems/actions.cairo

✓ Project built successfully (sozo build)
✓ Verification job submitted: abc-123-def-456

⏳ Checking verification status...

 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%  ⏱ 01:15

✓ Verification successful!

╭─────────────────────────────────────────╮
│ Verification Status                     │
├─────────────────────────────────────────┤
│ Status:      Success                    │
│ Job ID:      abc-123-def-456            │
│ Class Hash:  0x044dc2b3...              │
│ Contract:    actions                    │
│ Network:     sepolia                    │
│ Build Tool:  sozo                       │
╰─────────────────────────────────────────╯

View on Voyager: https://sepolia.voyager.online/class/0x044dc2b3...
```

### Verification on Voyager Website

Visit Voyager to see:
- Full source code for models and systems
- Dojo version information
- World contract relationships
- Model schemas
- System interfaces

## Troubleshooting

### Error: "Dojo version not found"

**Problem:** Cannot detect Dojo version from `Scarb.toml`

**Solutions:**

1. **Add explicit Dojo dependency:**
   ```toml
   [dependencies]
   dojo = "1.7.2"  # Explicit version
   ```

2. **Or use `--project-type dojo` flag:**
   ```bash
   voyager verify \
       --network sepolia \
       --class-hash <HASH> \
       --contract-name actions \
       --project-type dojo
   ```

3. **Check Dojo installation:**
   ```bash
   sozo --version
   ```

### Error: "sierra-replace-ids not enabled"

**Problem:** Build fails because `sierra-replace-ids` is missing

**Solution:** Add to `Scarb.toml`:
```toml
[cairo]
sierra-replace-ids = true
```

This is **required** for all Dojo projects.

### Error: "Cairo version mismatch"

**Problem:** Cairo version incompatible with Dojo version

**Solutions:**

1. **Check compatibility:**
   - Dojo 1.7.x requires Cairo 2.12.x
   - Dojo 2.0.x requires Cairo 2.13.x+

2. **Update `cairo-version` in `Scarb.toml`:**
   ```toml
   [package]
   cairo-version = "2.12.2"  # Match Dojo requirements
   ```

3. **Verify locally first:**
   ```bash
   sozo build  # Should succeed without errors
   ```

### Error: "sozo command not found"

**Problem:** Dojo not installed or not in PATH

**Solutions:**

1. **Install Dojo:**
   ```bash
   curl -L https://install.dojoengine.org | bash
   dojoup
   ```

2. **Verify installation:**
   ```bash
   sozo --version
   ```

3. **Note:** Voyager can still verify Dojo projects even if sozo isn't installed locally (remote build handles it)

### Error: "World contract verification failed"

**Problem:** Trying to verify the world contract itself

**Solution:** You typically don't need to verify the world contract separately. Focus on verifying:
- Your game systems (contracts)
- Your models (if deployed as separate contracts)

The world contract is a standard Dojo component that doesn't need individual verification.

### Error: "Build-external-contracts missing"

**Problem:** World contract not being built

**Solution:** Add to `Scarb.toml`:
```toml
[[target.starknet-contract]]
build-external-contracts = ["dojo::world::world_contract::world"]
```

### Verification Takes Longer Than Expected

**Problem:** Dojo projects have more dependencies and take longer to compile

**Expected Times:**
- Simple Dojo project: 1-2 minutes
- Complex Dojo world: 3-5 minutes

**Tips:**
- Always use `--watch` to monitor progress
- Use `--verbose` to see build output
- Check status with `voyager history status --job <JOB_ID>`

### Error: "Dojo plugin version mismatch"

**Problem:** Cairo macros plugin version doesn't match Dojo version

**Solution:** Ensure versions match in `Scarb.toml`:
```toml
[package]
version = "1.7.2"  # Match Dojo version

[dependencies]
dojo = "1.7.2"     # Same version

[tool.scarb]
allow-prebuilt-plugins = ["dojo_cairo_macros"]
```

## Best Practices

### 1. Always Specify Cairo Version

Dojo requires exact Cairo versions:

```toml
[package]
cairo-version = "2.12.2"  # Required, not optional
```

### 2. Use sierra-replace-ids

Always enable this for Dojo:

```toml
[cairo]
sierra-replace-ids = true
```

### 3. Keep Dojo and Dependencies in Sync

All versions should align:

```toml
[package]
version = "1.7.2"
cairo-version = "2.12.2"

[dependencies]
starknet = "2.12.2"
dojo = "1.7.2"

[dev-dependencies]
cairo_test = "2.12.2"
dojo_cairo_test = "1.7.2"
```

### 4. Verify Systems, Not Models

Focus verification on:
- **Systems** (game logic contracts) - Important to verify
- **Complex models** - If they have custom logic

Skip verification for:
- Simple data models without logic
- Standard Dojo components

### 5. Use Batch Verification for Worlds

Verify all your game contracts together:

```toml
[voyager]
project-type = "dojo"

[[contracts]]
contract-name = "actions"
class-hash = "0x..."

[[contracts]]
contract-name = "items"
class-hash = "0x..."
```

### 6. Test Locally Before Verification

Always ensure local build succeeds:

```bash
# Clean build
sozo clean
sozo build

# Should complete without errors
echo $?  # Should output: 0
```

### 7. Use Configuration Files for Complex Worlds

For projects with many contracts, use `.voyager.toml`:

```toml
[voyager]
network = "sepolia"
license = "MIT"
project-type = "dojo"
watch = true
verbose = false

[[contracts]]
# ... all your contracts
```

Commit this to version control for your team.

### 8. Verify on Testnet First

Always test on Sepolia before mainnet:

```bash
# Deploy to testnet
sozo migrate --network sepolia

# Verify on testnet
voyager verify \
    --network sepolia \
    --class-hash <SEPOLIA_HASH> \
    --contract-name actions

# Only after success, deploy and verify on mainnet
```

### 9. Monitor Verification Progress

Use watch mode for immediate feedback:

```bash
voyager verify \
    --network sepolia \
    --class-hash <HASH> \
    --contract-name actions \
    --watch \
    --verbose  # See detailed build output
```

### 10. Document Your World Structure

Include verification info in your project README:

```markdown
## Verified Contracts

- **actions**: [View on Voyager](https://sepolia.voyager.online/class/0x044dc2...)
- **items**: [View on Voyager](https://sepolia.voyager.online/class/0x055dc2...)
```

## Common Dojo Patterns

### Pattern 1: Simple Game World

```
dojo-world/
├── Scarb.toml
└── src/
    ├── lib.cairo
    ├── models.cairo       # All models in one file
    └── systems/
        └── actions.cairo  # Single actions system
```

**Verification:**
```bash
voyager verify --class-hash <HASH> --contract-name actions
```

### Pattern 2: Complex Multi-System World

```
dojo-world/
├── Scarb.toml
└── src/
    ├── lib.cairo
    ├── models/
    │   ├── player.cairo
    │   ├── items.cairo
    │   └── map.cairo
    └── systems/
        ├── player_actions.cairo
        ├── combat.cairo
        └── trading.cairo
```

**Verification:** Use batch `.voyager.toml` for all systems

### Pattern 3: Dojo with External Dependencies

```toml
[dependencies]
starknet = "2.12.2"
dojo = "1.7.2"
openzeppelin = "0.15.0"  # Additional dependencies work fine
```

Voyager handles all dependencies automatically.

## Next Steps

Congratulations! You've successfully verified a Dojo project. Here's what to explore next:

1. **[Multi-Contract Batch](./multi-contract.md)** - Efficient batch verification for complex worlds
2. **[CI/CD Integration](./ci-pipeline.md)** - Automate Dojo verification in your deployment pipeline
3. **[Workspace Projects](./workspace-project.md)** - Learn about multi-package Scarb workspaces
4. **[Configuration Guide](../configuration/config-file.md)** - Deep dive into all configuration options
5. **[History Tracking](../commands/history.md)** - Track verification history for your Dojo world

## Additional Resources

- **[Dojo Book](https://book.dojoengine.org)** - Official Dojo documentation
- **[Dojo Installation](https://book.dojoengine.org/getting-started/quick-start)** - Install Dojo and sozo
- **[Supported Versions](../reference/supported-versions.md)** - Dojo/Cairo compatibility matrix
- **[Troubleshooting Guide](../troubleshooting/README.md)** - Comprehensive error resolution
- **[Command Reference](../commands/verify.md)** - Complete verify command options
- **[Dojo Discord](https://discord.gg/dojoengine)** - Get help from the Dojo community
- **[Voyager Telegram](https://t.me/StarknetVoyager)** - Voyager support channel

## FAQ

**Q: Do I need to verify the world contract?**

A: No, the world contract is a standard Dojo component. Focus on verifying your custom systems and models.

**Q: Can I verify Dojo projects without sozo installed?**

A: Yes! Voyager handles the build remotely. Local sozo is optional but recommended for testing.

**Q: How long does Dojo verification take?**

A: Typically 1-2 minutes for simple projects, 3-5 minutes for complex worlds with many models/systems.

**Q: What if my Dojo version isn't detected?**

A: Use `--project-type dojo` to explicitly specify. Voyager will still verify successfully.

**Q: Can I use Dojo with workspaces?**

A: Yes! Use `--package <name>` to specify which package in your workspace is the Dojo project.

**Q: Should I verify every model?**

A: Focus on systems (game logic). Simple data models don't need verification unless they have complex logic.

**Q: What about Dojo plugins and custom macros?**

A: Voyager handles standard Dojo macros automatically. Custom plugins should work if they're in your dependencies.

**Q: Can I verify Dojo contracts on mainnet?**

A: Yes, use `--network mainnet`. Always test on Sepolia first to ensure everything works.

**Q: How do I verify contracts from older Dojo versions?**

A: Specify the exact versions in `Scarb.toml`. Voyager supports older Dojo versions (check [Supported Versions](../reference/supported-versions.md)).

**Q: What if verification fails with "compilation error"?**

A: First verify that `sozo build` works locally. Check that all versions match and `sierra-replace-ids` is enabled.

---

**Building a Dojo game?** Join the [Dojo Discord](https://discord.gg/dojoengine) to connect with other provable game developers!
