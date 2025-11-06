# Getting Support

Need help with Voyager Verifier? This guide shows you where to get assistance and how to report issues effectively.

## Quick Support Overview

```
Need Help?
     ↓
┌────────────────────────────────────────┐
│  Try Self-Help First                   │
│  • Check documentation                 │
│  • Review common errors                │
│  • Use debugging tools                 │
└────────────────────────────────────────┘
     ↓
Still Stuck?
     ↓
┌────────────────────────────────────────┐
│  Community Support                     │
│  • Telegram for quick questions        │
│  • GitHub for bug reports/features     │
└────────────────────────────────────────┘
```

---

## Self-Help Resources

Before reaching out for help, try these resources:

### 1. Documentation

**Start Here:**
```bash
# View documentation at:
# https://docs.voyager.nethermind.io
```

**Key Sections:**
- [Common Errors](common-errors.md) - Quick fixes for frequent problems
- [Debugging Guide](debugging.md) - Systematic troubleshooting workflow
- [Error Codes](../reference/error-codes.md) - Complete error reference
- [Verbose Mode](verbose-mode.md) - Understanding detailed output

### 2. Built-in Help

```bash
# General help
voyager verify --help

# Status command help
voyager status --help

# History command help
voyager history --help
```

### 3. Dry-Run Mode

Test your command without submitting:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run
```

### 4. Verbose Output

Get detailed error information:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose
```

---

## Community Support

### Telegram Community

**Join the Starknet Voyager Telegram group for:**
- Quick questions and answers
- Community discussions
- General usage help
- Tips and best practices

**Link:** [https://t.me/StarknetVoyager](https://t.me/StarknetVoyager)

**When to Use Telegram:**
- ✅ Quick questions about usage
- ✅ Clarification on features
- ✅ General troubleshooting help
- ✅ Community discussions
- ❌ Detailed bug reports (use GitHub instead)
- ❌ Feature requests (use GitHub instead)

**Tips for Getting Help on Telegram:**

1. **Search First**: Check if your question has been asked before
2. **Be Specific**: Include error messages and what you tried
3. **Share Context**: Network, contract details (redact sensitive info)
4. **Be Patient**: Community members help voluntarily

**Example Good Question:**
```
I'm getting "Compilation failed" when verifying on mainnet.
Using voyager 0.5.0 with Scarb 2.8.2.
Error: error[E0005]: Module file not found. Expected path: /tmp/.../src/tests.cairo

I tried adding --test-files but still failing. Any ideas?
```

**Example Poor Question:**
```
It doesn't work. Help?
```

---

## GitHub Issues

**Repository:** [https://github.com/NethermindEth/voyager-verifier](https://github.com/NethermindEth/voyager-verifier)

### Reporting Bugs

**When to Report:**
- Tool crashes or hangs
- Incorrect behavior
- Error messages that don't make sense
- Verification fails when it should succeed

**Before Reporting:**

1. **Search Existing Issues**: Your bug might already be reported
   - Check open issues: `is:issue is:open`
   - Check closed issues: `is:issue is:closed`

2. **Verify It's a Bug**: Test with minimal reproduction
   ```bash
   # Try with verbose mode
   voyager verify --verbose ...

   # Try with dry-run
   voyager verify --dry-run ...
   ```

3. **Gather Information**: Collect diagnostic details

**How to Report a Bug:**

Create a GitHub issue with this template:

```markdown
## Bug Description
[Clear, concise description of what went wrong]

## Steps to Reproduce
1. Command executed: `voyager verify --network mainnet ...`
2. Expected behavior: [What should happen]
3. Actual behavior: [What actually happened]

## Environment
- Voyager Version: [Run `voyager --version`]
- Operating System: [Linux/macOS/Windows]
- Scarb Version: [Run `scarb --version`]
- Cairo Version: [From Scarb.toml]

## Error Output
```
[Paste full error output, including --verbose output if available]
```

## Additional Context
- Config file used (if any)
- Network: mainnet/sepolia/custom
- Project structure (if relevant)

## Reproducible Example
[Link to minimal repository that reproduces the issue, if possible]
```

**Example Bug Report:**

```markdown
## Bug Description
Verification fails with "Class hash mismatch" but hashes are identical

## Steps to Reproduce
1. Run: `voyager verify --network mainnet --class-hash 0x044dc2b3... --contract-name Counter`
2. Expected: Verification succeeds
3. Actual: Error E030: Class hash mismatch

## Environment
- Voyager Version: 0.5.0
- Operating System: Ubuntu 22.04
- Scarb Version: 2.8.2
- Cairo Version: 2.8.2

## Error Output
```
[E030] Class hash mismatch. Compiled: 0x044dc2b3..., Expected: 0x044dc2b3...
```

## Additional Context
- Using default config
- Network: mainnet
- Scarb.lock file is present and committed

## Reproducible Example
https://github.com/example/minimal-repro
```

### Requesting Features

**When to Request:**
- New functionality ideas
- Improvements to existing features
- Better error messages
- Documentation enhancements

**How to Request a Feature:**

```markdown
## Feature Description
[Clear description of the proposed feature]

## Use Case
[Why is this feature needed? What problem does it solve?]

## Proposed Solution
[How you envision this working]

## Alternatives Considered
[Other approaches you thought about]

## Additional Context
[Examples, mockups, or related features in other tools]
```

**Example Feature Request:**

```markdown
## Feature Description
Add support for verifying multiple contracts in a single command

## Use Case
When deploying a project with multiple contracts, it's tedious to verify each one separately.
I want to verify all contracts in one command.

## Proposed Solution
```bash
voyager verify --network mainnet \
  --batch contracts.json
```

Where contracts.json contains:
```json
[
  {"class_hash": "0x123...", "contract_name": "Counter"},
  {"class_hash": "0x456...", "contract_name": "ERC20"}
]
```

## Alternatives Considered
- Using shell scripts to loop through contracts (current workaround)
- Using the batch verification API endpoint directly

## Additional Context
Similar to how `scarb build` handles multiple packages
```

---

## Before Asking for Help

Complete this checklist before reaching out:

### ✅ Pre-Support Checklist

- [ ] **Read the error message carefully**: What is it telling you?
- [ ] **Check the documentation**: Especially [Common Errors](common-errors.md)
- [ ] **Try verbose mode**: Get detailed output with `--verbose`
- [ ] **Use dry-run mode**: Preview what will be submitted with `--dry-run`
- [ ] **Verify your setup**: Check versions, network, config
- [ ] **Search existing issues**: Has someone else reported this?
- [ ] **Create minimal reproduction**: Simplify to the smallest failing case
- [ ] **Gather version information**: Voyager, Scarb, Cairo versions

---

## What Information to Include

When asking for help, always include:

### Essential Information

```bash
# 1. Voyager version
voyager --version

# 2. Scarb version
scarb --version

# 3. Full command you ran
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# 4. Full error output (with --verbose)
voyager verify --verbose ...

# 5. Your environment
uname -a  # Linux/macOS
# or
ver  # Windows
```

### Additional Context

- **Network**: mainnet, sepolia, or custom endpoint
- **Config file**: If using `.voyager.toml`
- **Project structure**: Multi-package workspace or single package?
- **Recent changes**: Did this work before? What changed?
- **Workarounds tried**: What have you attempted so far?

### What NOT to Include

- ⚠️ **Private keys or secrets**
- ⚠️ **API keys or tokens**
- ⚠️ **Sensitive contract code** (unless necessary for reproduction)

**Redact Sensitive Information:**

```bash
# Good - Shows structure without exposing secrets
--class-hash 0x044dc2b3...
--endpoint https://api.custom.com

# Bad - Exposes full sensitive data
--class-hash 0x044dc2b3abc123def456789... (full hash when not needed)
--endpoint https://api.company-internal.com/secret-key-abc123
```

---

## Getting Help Effectively

### Do's ✅

1. **Be Specific**
   ```
   ❌ "Verification doesn't work"
   ✅ "Verification fails with E030 (class hash mismatch) on mainnet"
   ```

2. **Provide Context**
   ```
   ❌ "Getting an error"
   ✅ "Getting error E005 (module not found) when verifying a contract
       with test files in src/tests.cairo. Using --test-files flag."
   ```

3. **Show What You Tried**
   ```
   ❌ "How do I fix this?"
   ✅ "I tried:
       1. Adding --test-files flag - still failing
       2. Checking file exists - it's there
       3. Running with --verbose - shows file path is correct
       What else should I try?"
   ```

4. **Use Code Blocks**
   ```
   ✅ Format commands and output in code blocks for readability
   ```

5. **Follow Up**
   - If solution works, confirm and thank
   - If still stuck, provide additional details requested
   - Close GitHub issues when resolved

### Don'ts ❌

1. **Don't Spam Multiple Channels**
   - Choose one channel (Telegram OR GitHub)
   - Don't cross-post the same question immediately

2. **Don't Expect Instant Responses**
   - Community members help voluntarily
   - GitHub issues may take time to triage

3. **Don't Post Huge Logs Without Context**
   - Provide relevant excerpts
   - Use GitHub Gists for very long logs

4. **Don't Hijack Other Threads**
   - Create a new issue if your problem is different
   - Don't add unrelated questions to existing issues

5. **Don't Give Up Too Quickly**
   - Work through the debugging checklist
   - Try the suggestions provided

---

## Response Times

**Typical response times:**

| Channel | Type | Expected Response |
|---------|------|-------------------|
| Telegram | Quick Question | Minutes to hours |
| Telegram | Complex Issue | Hours to days |
| GitHub | Bug Report | Days to weeks |
| GitHub | Feature Request | Weeks to months |

**Remember:**
- These are community projects
- Contributors help voluntarily
- Response times vary by complexity and availability

---

## Contributing

Found a bug? Want to improve the tool? Consider contributing!

**How to Contribute:**

1. **Report Issues**: Detailed bug reports help improve the tool
2. **Documentation**: Suggest improvements or fix typos
3. **Code**: Submit pull requests for bug fixes or features
4. **Community**: Help others on Telegram

**See the repository for contribution guidelines:**
[https://github.com/NethermindEth/voyager-verifier](https://github.com/NethermindEth/voyager-verifier)

---

## Emergency Support

For critical production issues:

1. **Check Status Page**: Verify API status
   ```bash
   curl https://api.voyager.online/api-docs
   ```

2. **Try Alternative Network**: If mainnet fails, test on sepolia
   ```bash
   voyager verify --network sepolia ...
   ```

3. **Use Dry-Run**: Ensure your submission is correct
   ```bash
   voyager verify --dry-run ...
   ```

4. **Report on GitHub**: For critical bugs affecting many users

---

## Additional Resources

### Official Links

- **Documentation**: https://docs.voyager.nethermind.io
- **GitHub**: https://github.com/NethermindEth/voyager-verifier
- **Telegram**: https://t.me/StarknetVoyager
- **Voyager Explorer**: https://voyager.online

### Related Resources

- **Starknet Documentation**: https://docs.starknet.io
- **Scarb Documentation**: https://docs.swmansion.com/scarb
- **Cairo Documentation**: https://book.cairo-lang.org

---

## Support Quick Reference

| Need | Channel | When to Use |
|------|---------|-------------|
| Quick question | [Telegram](https://t.me/StarknetVoyager) | General usage, tips |
| Bug report | [GitHub Issues](https://github.com/NethermindEth/voyager-verifier/issues) | Tool defects |
| Feature request | [GitHub Issues](https://github.com/NethermindEth/voyager-verifier/issues) | New functionality |
| Documentation | [Docs Site](common-errors.md) | Self-help first |
| API issues | GitHub Issues | API problems |

---

## See Also

- [Common Errors](common-errors.md) - Solutions to frequent problems
- [Debugging Guide](debugging.md) - Systematic troubleshooting
- [Error Codes](../reference/error-codes.md) - Complete error reference
- [Verbose Mode](verbose-mode.md) - Understanding detailed output
