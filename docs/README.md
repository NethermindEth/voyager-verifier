# Voyager Verifier Documentation

This directory contains the source files for the Voyager Verifier documentation, built using [mdBook](https://rust-lang.github.io/mdBook/).

## Local Development

### Prerequisites

Install mdBook:

```bash
cargo install mdbook
```

### Build the Documentation

Build the documentation:

```bash
cd docs
mdbook build
```

The generated documentation will be in the `../book/` directory.

### Serve Locally

Serve the documentation with live-reload:

```bash
cd docs
mdbook serve
```

Then open your browser to `http://localhost:3000`.

### Watch for Changes

mdBook automatically watches for file changes when using `serve`. Any edits to `.md` files will trigger an automatic rebuild and browser refresh.

## Documentation Structure

```
docs/
├── book.toml              # mdBook configuration
├── src/                   # Documentation source files
│   ├── SUMMARY.md         # Table of contents
│   ├── introduction.md    # Introduction page
│   ├── getting-started/   # Installation and quickstart
│   ├── commands/          # Command reference
│   ├── verification/      # Verification methods (Phase 2+)
│   ├── configuration/     # Configuration guide (Phase 2+)
│   ├── history/           # History documentation (Phase 2+)
│   ├── advanced/          # Advanced features (Phase 3+)
│   ├── troubleshooting/   # Troubleshooting guide (Phase 4+)
│   ├── examples/          # Practical examples (Phase 5+)
│   ├── reference/         # Reference material (Phase 4+)
│   └── contributing/      # Contributing guide (Phase 5+)
└── README.md              # This file
```

## Content Status

### ✅ Phase 1 Complete (Core Documentation)

- Introduction
- Installation (asdf, Cargo)
- System requirements
- Quickstart guide
- Command reference (verify, status, history)

### 🚧 Phase 2-5 In Progress

Additional sections will be added in subsequent phases:

- Phase 2: Feature Documentation (Batch, History, Notifications, Watch Mode)
- Phase 3: Advanced Features (Workspaces, Dojo, CI/CD)
- Phase 4: Troubleshooting & Reference (Error codes, Debugging)
- Phase 5: Examples & Polish (Walkthroughs, Best practices)

## Contributing

When adding or updating documentation:

1. Follow the existing style and formatting
2. Keep sentences short and scannable
3. Include code examples where helpful
4. Test all commands and examples
5. Update SUMMARY.md if adding new pages
6. Build and preview locally before committing

## Deployment

Documentation is automatically deployed to GitHub Pages via GitHub Actions when changes are pushed to the `main` or `documentation` branch.

See `.github/workflows/deploy-docs.yml` for deployment configuration.

## Style Guidelines

- Use present tense ("verify" not "verifies")
- Use active voice ("run the command" not "the command is run")
- Keep technical jargon to a minimum
- Explain concepts before diving into commands
- Include examples for every feature
- Use callout boxes for warnings and tips
- Cross-reference related sections

## File Naming

- Use lowercase with hyphens: `my-page.md`
- Match directory names to sections: `getting-started/`, `commands/`
- Use `README.md` for section index pages

## Markdown Extensions

mdBook supports:

- Standard CommonMark
- GitHub-flavored tables
- Task lists
- Strikethrough
- Code syntax highlighting
- Admonitions (info, warning, danger blocks)

See [mdBook documentation](https://rust-lang.github.io/mdBook/) for full feature list.
