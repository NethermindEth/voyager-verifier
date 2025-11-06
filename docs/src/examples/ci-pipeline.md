# CI/CD Pipeline Integration

This example demonstrates how to integrate voyager-verifier into CI/CD pipelines for automated contract verification. Automate verification to ensure every deployment is verified consistently, without manual intervention.

## Overview

You'll learn how to:
- Integrate verification into GitHub Actions, GitLab CI, CircleCI, and Jenkins
- Deploy and verify contracts automatically
- Handle verification failures in CI
- Configure secrets and environment variables
- Use batch verification in CI
- Set up notifications and status reporting
- Implement deployment gates and approval workflows

**Time Required:** 25-30 minutes

**Difficulty:** Advanced

## Why Automate Verification in CI/CD?

### Benefits of Automated Verification

**Consistency** - Every deployment is verified using the same process, eliminating human error.

**Speed** - Verification happens automatically during deployment, no manual steps needed.

**Transparency** - Team can see verification status in CI logs and pull requests.

**Quality Gate** - Treat verification as a required step, failing builds if verification fails.

**Audit Trail** - CI systems provide complete logs and history of all verifications.

**Team Efficiency** - Developers don't need to remember to verify manually.

### When to Verify

**After Deployment to Testnet** - Verify every testnet deployment to catch issues early.

**After Deployment to Mainnet** - Critical - ensure mainnet contracts are always verified.

**On PR Merges** - Verify when code is merged to main/production branches.

**On Tagged Releases** - Verify official releases automatically.

**After Successful Tests** - Only verify if deployment tests pass.

## Prerequisites

Before setting up CI/CD verification, ensure you have:

- voyager-verifier CLI installed in your CI environment
- Starknet deployment tooling (starkli, sncast, or custom scripts)
- Class hashes from deployment (captured in deployment step)
- Repository secrets/environment variables configured:
  - Network selection (mainnet/sepolia)
  - Deployment credentials (if needed)
  - Class hashes or deployment manifest

## Key Concepts

### CI/CD Workflow Design

**Deploy → Verify Pattern** - Most common approach:
1. Build contracts with Scarb
2. Deploy to Starknet
3. Capture class hash from deployment
4. Verify with voyager-verifier
5. Report results

**Verification as Quality Gate** - Fail the build if verification fails:
- Use `--watch` to wait for completion
- Check exit code (0 = success, non-zero = failure)
- Display verification status in logs
- Send notifications on failure

**Parallel vs Sequential** - Design considerations:
- **Sequential**: Deploy → Wait → Verify → Complete (safer, slower)
- **Parallel**: Deploy multiple contracts → Verify all in batch (faster)

### Configuration Management

**Using .voyager.toml** - Commit configuration to repository:
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
verbose = true
```

**Environment-Specific Configs** - Different configs for dev/staging/prod:
- `.voyager.dev.toml` - For development
- `.voyager.staging.toml` - For staging
- `.voyager.prod.toml` - For production

**Dynamic Configuration** - Generate config from deployment output:
- Parse deployment manifest
- Extract class hashes
- Create temporary .voyager.toml
- Run verification

## Example 1: GitHub Actions

GitHub Actions is the most popular CI/CD platform for open-source projects. This example shows a complete workflow for deploying and verifying Starknet contracts.

### Complete Workflow File

Create `.github/workflows/verify-contracts.yml`:

```yaml
name: Deploy and Verify Contracts

on:
  push:
    branches:
      - main
      - production
    tags:
      - 'v*'
  pull_request:
    branches:
      - main
  workflow_dispatch:
    inputs:
      network:
        description: 'Network to deploy to'
        required: true
        default: 'sepolia'
        type: choice
        options:
          - sepolia
          - mainnet

env:
  SCARB_VERSION: '2.8.4'
  VOYAGER_VERSION: '2.0.0'

jobs:
  build:
    name: Build Contracts
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Scarb
        uses: software-mansion/setup-scarb@v1
        with:
          scarb-version: ${{ env.SCARB_VERSION }}

      - name: Build contracts
        run: |
          scarb --release build
          echo "Build completed successfully"

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: compiled-contracts
          path: |
            target/release/*.json
            target/release/*.sierra.json
          retention-days: 7

  deploy:
    name: Deploy Contracts
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: ${{ github.event.inputs.network || (github.ref == 'refs/heads/production' && 'mainnet' || 'sepolia') }}

    outputs:
      class_hash: ${{ steps.deploy.outputs.class_hash }}
      network: ${{ steps.set_network.outputs.network }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          name: compiled-contracts
          path: target/release/

      - name: Set network
        id: set_network
        run: |
          if [ "${{ github.event_name }}" == "workflow_dispatch" ]; then
            echo "network=${{ github.event.inputs.network }}" >> $GITHUB_OUTPUT
          elif [ "${{ github.ref }}" == "refs/heads/production" ]; then
            echo "network=mainnet" >> $GITHUB_OUTPUT
          else
            echo "network=sepolia" >> $GITHUB_OUTPUT
          fi

      - name: Setup Starkli
        run: |
          curl https://get.starkli.sh | sh
          export PATH="$HOME/.starkli/bin:$PATH"
          starkliup -v 0.3.5

      - name: Deploy contract
        id: deploy
        env:
          STARKNET_ACCOUNT: ${{ secrets.STARKNET_ACCOUNT }}
          STARKNET_KEYSTORE: ${{ secrets.STARKNET_KEYSTORE }}
          NETWORK: ${{ steps.set_network.outputs.network }}
        run: |
          export PATH="$HOME/.starkli/bin:$PATH"

          # Set RPC URL based on network
          if [ "$NETWORK" == "mainnet" ]; then
            RPC_URL="https://starknet-mainnet.public.blastapi.io"
          else
            RPC_URL="https://starknet-sepolia.public.blastapi.io"
          fi

          # Deploy contract and capture class hash
          OUTPUT=$(starkli declare \
            target/release/my_contract_MyContract.contract_class.json \
            --rpc $RPC_URL \
            --account ~/.starkli-wallets/deployer/account.json \
            --keystore ~/.starkli-wallets/deployer/keystore.json 2>&1)

          echo "$OUTPUT"

          # Extract class hash from output
          CLASS_HASH=$(echo "$OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")

          if [ -z "$CLASS_HASH" ]; then
            echo "Error: Failed to extract class hash from deployment output"
            exit 1
          fi

          echo "Deployed class hash: $CLASS_HASH"
          echo "class_hash=$CLASS_HASH" >> $GITHUB_OUTPUT

          # Save deployment info
          echo "{\"class_hash\": \"$CLASS_HASH\", \"network\": \"$NETWORK\", \"timestamp\": \"$(date -Iseconds)\"}" > deployment.json

      - name: Upload deployment info
        uses: actions/upload-artifact@v4
        with:
          name: deployment-info
          path: deployment.json
          retention-days: 30

  verify:
    name: Verify Contracts
    needs: deploy
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Scarb
        uses: software-mansion/setup-scarb@v1
        with:
          scarb-version: ${{ env.SCARB_VERSION }}

      - name: Install voyager-verifier
        run: |
          curl -L https://raw.githubusercontent.com/NethermindEth/voyager-verify/main/install.sh | bash
          echo "$HOME/.voyager/bin" >> $GITHUB_PATH

      - name: Verify version
        run: voyager --version

      - name: Download deployment info
        uses: actions/download-artifact@v4
        with:
          name: deployment-info

      - name: Verify contract
        env:
          CLASS_HASH: ${{ needs.deploy.outputs.class_hash }}
          NETWORK: ${{ needs.deploy.outputs.network }}
        run: |
          echo "Verifying contract on $NETWORK"
          echo "Class hash: $CLASS_HASH"

          voyager verify \
            --network $NETWORK \
            --class-hash $CLASS_HASH \
            --contract-name MyContract \
            --license MIT \
            --watch \
            --verbose

          VERIFY_EXIT=$?

          if [ $VERIFY_EXIT -eq 0 ]; then
            echo "✓ Verification successful!"
            echo "View on Voyager: https://voyager.online/class/$CLASS_HASH"
          else
            echo "✗ Verification failed with exit code $VERIFY_EXIT"
            exit 1
          fi

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const classHash = '${{ needs.deploy.outputs.class_hash }}';
            const network = '${{ needs.deploy.outputs.network }}';

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `### ✅ Contract Verification Complete

              **Network:** ${network}
              **Class Hash:** \`${classHash}\`
              **Status:** Verified ✓

              [View on Voyager](https://voyager.online/class/${classHash})`
            });

      - name: Create verification badge
        if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/production'
        run: |
          mkdir -p .github/badges
          echo '{"schemaVersion": 1, "label": "contract", "message": "verified", "color": "success"}' > .github/badges/verification.json

  notify:
    name: Send Notifications
    needs: [deploy, verify]
    runs-on: ubuntu-latest
    if: always()

    steps:
      - name: Notify Slack
        if: success()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "✅ Contract verified successfully",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Contract Verification Successful*\n\n*Network:* ${{ needs.deploy.outputs.network }}\n*Class Hash:* `${{ needs.deploy.outputs.class_hash }}`\n*Branch:* ${{ github.ref_name }}\n\n<https://voyager.online/class/${{ needs.deploy.outputs.class_hash }}|View on Voyager>"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}

      - name: Notify on failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "❌ Contract verification failed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Contract Verification Failed*\n\n*Network:* ${{ needs.deploy.outputs.network }}\n*Branch:* ${{ github.ref_name }}\n\n<${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Logs>"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Features Demonstrated

**Matrix Builds** - Verify multiple contracts in parallel:

```yaml
verify:
  name: Verify Contracts
  needs: deploy
  runs-on: ubuntu-latest
  strategy:
    matrix:
      contract:
        - name: Token
          class_hash: ${{ needs.deploy.outputs.token_hash }}
        - name: Staking
          class_hash: ${{ needs.deploy.outputs.staking_hash }}
        - name: Governance
          class_hash: ${{ needs.deploy.outputs.governance_hash }}

  steps:
    - name: Verify ${{ matrix.contract.name }}
      run: |
        voyager verify \
          --network mainnet \
          --class-hash ${{ matrix.contract.class_hash }} \
          --contract-name ${{ matrix.contract.name }} \
          --watch --verbose
```

**Conditional Verification** - Only verify on specific branches:

```yaml
verify:
  name: Verify Contracts
  needs: deploy
  runs-on: ubuntu-latest
  if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')

  steps:
    - name: Verify contract
      run: voyager verify --network mainnet --class-hash $CLASS_HASH --contract-name MyContract --watch
```

**Secrets Management** - Secure handling of sensitive data:

```yaml
- name: Verify contract
  env:
    # Reference secrets securely
    VOYAGER_NETWORK: ${{ secrets.NETWORK }}
    CLASS_HASH: ${{ secrets.CLASS_HASH }}
  run: |
    voyager verify \
      --network $VOYAGER_NETWORK \
      --class-hash $CLASS_HASH \
      --contract-name MyContract \
      --watch
```

### Setting Up GitHub Secrets

Configure secrets in your repository:

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Add the following secrets:
   - `STARKNET_ACCOUNT` - Your Starknet account JSON
   - `STARKNET_KEYSTORE` - Your keystore file
   - `SLACK_WEBHOOK_URL` - (Optional) For notifications
3. Add environment variables (optional):
   - `VOYAGER_NETWORK` - Default network (mainnet/sepolia)

### Expected Output

**Successful Verification:**

```
Run voyager verify \
  --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract \
  --watch \
  --verbose

✓ Files collected: 3 files
✓ Project built successfully
✓ Verification job submitted

Job ID: abc-123-def-456

⏳ Checking verification status...

 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%  ⏱ 00:47

✓ Verification successful!

╭─────────────────────────────────────────╮
│ Verification Status                     │
├─────────────────────────────────────────┤
│ Status:      Success                    │
│ Job ID:      abc-123-def-456            │
│ Class Hash:  0x044dc2b3...              │
│ Contract:    MyContract                 │
│ Network:     mainnet                    │
╰─────────────────────────────────────────╯

View on Voyager: https://voyager.online/class/0x044dc2b3...

✓ Verification successful!
View on Voyager: https://voyager.online/class/0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

## Example 2: GitLab CI

GitLab CI provides built-in CI/CD with powerful pipeline features. This example shows how to integrate verification into GitLab pipelines.

### Complete .gitlab-ci.yml

Create `.gitlab-ci.yml`:

```yaml
# GitLab CI Pipeline for Starknet Contract Verification

variables:
  SCARB_VERSION: "2.8.4"
  VOYAGER_VERSION: "2.0.0"
  CARGO_HOME: "${CI_PROJECT_DIR}/.cargo"

stages:
  - build
  - deploy
  - verify
  - report

# Cache dependencies for faster builds
cache:
  key: ${CI_COMMIT_REF_SLUG}
  paths:
    - .cargo/
    - target/

before_script:
  - echo "Starting pipeline for $CI_COMMIT_REF_NAME"

build:contracts:
  stage: build
  image: ubuntu:22.04

  before_script:
    - apt-get update && apt-get install -y curl git

  script:
    - echo "Installing Scarb"
    - curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh -s -- -v $SCARB_VERSION
    - export PATH="$HOME/.local/bin:$PATH"

    - echo "Building contracts"
    - scarb --version
    - scarb --release build

    - echo "Build completed successfully"
    - ls -la target/release/

  artifacts:
    name: "compiled-contracts-$CI_COMMIT_SHORT_SHA"
    paths:
      - target/release/*.json
      - target/release/*.sierra.json
    expire_in: 1 week

  only:
    - main
    - production
    - merge_requests
    - tags

deploy:testnet:
  stage: deploy
  image: ubuntu:22.04

  variables:
    NETWORK: "sepolia"

  environment:
    name: testnet
    url: https://sepolia.voyager.online

  before_script:
    - apt-get update && apt-get install -y curl jq

  script:
    - echo "Deploying to $NETWORK"

    # Install starkli
    - curl https://get.starkli.sh | sh
    - export PATH="$HOME/.starkli/bin:$PATH"
    - starkliup -v 0.3.5

    # Deploy contract
    - |
      OUTPUT=$(starkli declare \
        target/release/my_contract_MyContract.contract_class.json \
        --rpc https://starknet-sepolia.public.blastapi.io \
        --account $STARKNET_ACCOUNT_FILE \
        --keystore $STARKNET_KEYSTORE_FILE 2>&1)

    - echo "$OUTPUT"

    # Extract class hash
    - CLASS_HASH=$(echo "$OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
    - echo "Deployed class hash: $CLASS_HASH"

    # Save for next stage
    - echo $CLASS_HASH > class_hash.txt
    - echo "{\"class_hash\":\"$CLASS_HASH\",\"network\":\"$NETWORK\",\"commit\":\"$CI_COMMIT_SHA\"}" > deployment.json

  artifacts:
    paths:
      - class_hash.txt
      - deployment.json
    expire_in: 1 month

  only:
    - main
    - merge_requests

deploy:mainnet:
  stage: deploy
  image: ubuntu:22.04

  variables:
    NETWORK: "mainnet"

  environment:
    name: production
    url: https://voyager.online

  before_script:
    - apt-get update && apt-get install -y curl jq

  script:
    - echo "Deploying to $NETWORK"

    # Install starkli
    - curl https://get.starkli.sh | sh
    - export PATH="$HOME/.starkli/bin:$PATH"
    - starkliup -v 0.3.5

    # Deploy contract
    - |
      OUTPUT=$(starkli declare \
        target/release/my_contract_MyContract.contract_class.json \
        --rpc https://starknet-mainnet.public.blastapi.io \
        --account $STARKNET_ACCOUNT_FILE \
        --keystore $STARKNET_KEYSTORE_FILE 2>&1)

    - echo "$OUTPUT"

    # Extract class hash
    - CLASS_HASH=$(echo "$OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
    - echo "Deployed class hash: $CLASS_HASH"

    # Save for next stage
    - echo $CLASS_HASH > class_hash.txt
    - echo "{\"class_hash\":\"$CLASS_HASH\",\"network\":\"$NETWORK\",\"commit\":\"$CI_COMMIT_SHA\"}" > deployment.json

  artifacts:
    paths:
      - class_hash.txt
      - deployment.json
    expire_in: 1 month

  only:
    - production
    - tags

  when: manual  # Require manual approval for mainnet

verify:testnet:
  stage: verify
  image: ubuntu:22.04

  dependencies:
    - build:contracts
    - deploy:testnet

  before_script:
    - apt-get update && apt-get install -y curl

  script:
    - echo "Installing voyager-verifier"
    - curl -L https://raw.githubusercontent.com/NethermindEth/voyager-verify/main/install.sh | bash
    - export PATH="$HOME/.voyager/bin:$PATH"

    - echo "Verifying voyager-verifier installation"
    - voyager --version

    # Read class hash from artifact
    - CLASS_HASH=$(cat class_hash.txt)
    - echo "Verifying class hash: $CLASS_HASH"

    # Verify contract
    - |
      voyager verify \
        --network sepolia \
        --class-hash $CLASS_HASH \
        --contract-name MyContract \
        --license MIT \
        --watch \
        --verbose

    - |
      if [ $? -eq 0 ]; then
        echo "✓ Verification successful!"
        echo "View on Voyager: https://sepolia.voyager.online/class/$CLASS_HASH"
      else
        echo "✗ Verification failed"
        exit 1
      fi

  only:
    - main
    - merge_requests

verify:mainnet:
  stage: verify
  image: ubuntu:22.04

  dependencies:
    - build:contracts
    - deploy:mainnet

  before_script:
    - apt-get update && apt-get install -y curl

  script:
    - echo "Installing voyager-verifier"
    - curl -L https://raw.githubusercontent.com/NethermindEth/voyager-verify/main/install.sh | bash
    - export PATH="$HOME/.voyager/bin:$PATH"

    - echo "Verifying voyager-verifier installation"
    - voyager --version

    # Read class hash from artifact
    - CLASS_HASH=$(cat class_hash.txt)
    - echo "Verifying class hash: $CLASS_HASH"

    # Verify contract
    - |
      voyager verify \
        --network mainnet \
        --class-hash $CLASS_HASH \
        --contract-name MyContract \
        --license MIT \
        --watch \
        --verbose

    - |
      if [ $? -eq 0 ]; then
        echo "✓ Verification successful!"
        echo "View on Voyager: https://voyager.online/class/$CLASS_HASH"
      else
        echo "✗ Verification failed"
        exit 1
      fi

  only:
    - production
    - tags

report:verification:
  stage: report
  image: alpine:latest

  dependencies:
    - deploy:mainnet

  before_script:
    - apk add --no-cache curl jq

  script:
    - CLASS_HASH=$(cat class_hash.txt)
    - NETWORK=$(jq -r '.network' deployment.json)

    - echo "Verification Report"
    - echo "==================="
    - echo "Network: $NETWORK"
    - echo "Class Hash: $CLASS_HASH"
    - echo "Commit: $CI_COMMIT_SHA"
    - echo "Branch: $CI_COMMIT_REF_NAME"
    - echo "View: https://voyager.online/class/$CLASS_HASH"

    # Create badge
    - mkdir -p badges
    - echo '{"schemaVersion": 1, "label": "contract", "message": "verified", "color": "success"}' > badges/verification.json

  artifacts:
    paths:
      - badges/
    expire_in: 1 year

  only:
    - production
    - tags
```

### Variables & Secrets

Configure in GitLab: **Settings** → **CI/CD** → **Variables**

**Protected Variables** (only available on protected branches):
- `STARKNET_ACCOUNT_FILE` - Account configuration
- `STARKNET_KEYSTORE_FILE` - Keystore file
- Type: File

**Regular Variables**:
- `SCARB_VERSION` - Scarb version to use
- `VOYAGER_VERSION` - voyager-verifier version

### Pipeline Status Reporting

GitLab provides built-in status reporting:

```yaml
# Add status badge to README.md
[![Pipeline Status](https://gitlab.com/your-username/your-project/badges/main/pipeline.svg)](https://gitlab.com/your-username/your-project/-/pipelines)

[![Verification Status](https://gitlab.com/your-username/your-project/-/jobs/artifacts/main/raw/badges/verification.json?job=report:verification)](https://voyager.online)
```

## Example 3: CircleCI

CircleCI provides powerful workflow orchestration. This example shows how to verify contracts in CircleCI.

### Complete config.yml

Create `.circleci/config.yml`:

```yaml
# CircleCI Configuration for Starknet Contract Verification

version: 2.1

orbs:
  slack: circleci/slack@4.12.0

executors:
  ubuntu-executor:
    docker:
      - image: ubuntu:22.04
    resource_class: medium
    working_directory: ~/project

commands:
  install-scarb:
    description: "Install Scarb"
    parameters:
      version:
        type: string
        default: "2.8.4"
    steps:
      - run:
          name: Install Scarb
          command: |
            apt-get update && apt-get install -y curl
            curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh -s -- -v << parameters.version >>
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> $BASH_ENV

  install-voyager:
    description: "Install voyager-verifier"
    steps:
      - run:
          name: Install voyager-verifier
          command: |
            curl -L https://raw.githubusercontent.com/NethermindEth/voyager-verify/main/install.sh | bash
            echo 'export PATH="$HOME/.voyager/bin:$PATH"' >> $BASH_ENV

  install-starkli:
    description: "Install Starkli"
    steps:
      - run:
          name: Install Starkli
          command: |
            curl https://get.starkli.sh | sh
            echo 'export PATH="$HOME/.starkli/bin:$PATH"' >> $BASH_ENV
            source $HOME/.starkli/env
            starkliup -v 0.3.5

jobs:
  build:
    executor: ubuntu-executor

    steps:
      - checkout

      - install-scarb:
          version: "2.8.4"

      - restore_cache:
          keys:
            - scarb-cache-v1-{{ checksum "Scarb.toml" }}
            - scarb-cache-v1-

      - run:
          name: Build contracts
          command: |
            scarb --version
            scarb --release build
            ls -la target/release/

      - save_cache:
          key: scarb-cache-v1-{{ checksum "Scarb.toml" }}
          paths:
            - target/
            - ~/.cargo/

      - persist_to_workspace:
          root: .
          paths:
            - target/release/*.json
            - target/release/*.sierra.json

      - store_artifacts:
          path: target/release/
          destination: compiled-contracts

  deploy-testnet:
    executor: ubuntu-executor

    steps:
      - checkout

      - attach_workspace:
          at: .

      - install-starkli

      - run:
          name: Deploy to Sepolia
          command: |
            OUTPUT=$(starkli declare \
              target/release/my_contract_MyContract.contract_class.json \
              --rpc https://starknet-sepolia.public.blastapi.io \
              --account ~/.starkli-wallets/deployer/account.json \
              --keystore ~/.starkli-wallets/deployer/keystore.json 2>&1)

            echo "$OUTPUT"

            CLASS_HASH=$(echo "$OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")

            if [ -z "$CLASS_HASH" ]; then
              echo "Failed to extract class hash"
              exit 1
            fi

            echo "Deployed class hash: $CLASS_HASH"
            echo "$CLASS_HASH" > class_hash.txt
            echo "{\"class_hash\":\"$CLASS_HASH\",\"network\":\"sepolia\"}" > deployment.json

      - persist_to_workspace:
          root: .
          paths:
            - class_hash.txt
            - deployment.json

      - store_artifacts:
          path: deployment.json
          destination: deployment-info

  verify-testnet:
    executor: ubuntu-executor

    steps:
      - checkout

      - attach_workspace:
          at: .

      - install-scarb

      - install-voyager

      - run:
          name: Verify contract on Sepolia
          command: |
            CLASS_HASH=$(cat class_hash.txt)
            echo "Verifying class hash: $CLASS_HASH"

            voyager verify \
              --network sepolia \
              --class-hash $CLASS_HASH \
              --contract-name MyContract \
              --license MIT \
              --watch \
              --verbose

            VERIFY_EXIT=$?

            if [ $VERIFY_EXIT -eq 0 ]; then
              echo "✓ Verification successful!"
              echo "VERIFICATION_STATUS=success" >> verification_result.txt
              echo "VOYAGER_URL=https://sepolia.voyager.online/class/$CLASS_HASH" >> verification_result.txt
            else
              echo "✗ Verification failed"
              echo "VERIFICATION_STATUS=failed" >> verification_result.txt
              exit 1
            fi

      - persist_to_workspace:
          root: .
          paths:
            - verification_result.txt

      - slack/notify:
          event: pass
          custom: |
            {
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "✅ *Contract Verified Successfully*\n\n*Network:* Sepolia\n*Class Hash:* `$(cat class_hash.txt)`\n\n<https://sepolia.voyager.online/class/$(cat class_hash.txt)|View on Voyager>"
                  }
                }
              ]
            }

      - slack/notify:
          event: fail
          custom: |
            {
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "❌ *Contract Verification Failed*\n\n*Network:* Sepolia\n*Branch:* $CIRCLE_BRANCH\n\n<$CIRCLE_BUILD_URL|View Logs>"
                  }
                }
              ]
            }

  deploy-mainnet:
    executor: ubuntu-executor

    steps:
      - checkout

      - attach_workspace:
          at: .

      - install-starkli

      - run:
          name: Deploy to Mainnet
          command: |
            OUTPUT=$(starkli declare \
              target/release/my_contract_MyContract.contract_class.json \
              --rpc https://starknet-mainnet.public.blastapi.io \
              --account ~/.starkli-wallets/deployer/account.json \
              --keystore ~/.starkli-wallets/deployer/keystore.json 2>&1)

            echo "$OUTPUT"

            CLASS_HASH=$(echo "$OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")

            if [ -z "$CLASS_HASH" ]; then
              echo "Failed to extract class hash"
              exit 1
            fi

            echo "Deployed class hash: $CLASS_HASH"
            echo "$CLASS_HASH" > class_hash.txt
            echo "{\"class_hash\":\"$CLASS_HASH\",\"network\":\"mainnet\"}" > deployment.json

      - persist_to_workspace:
          root: .
          paths:
            - class_hash.txt
            - deployment.json

  verify-mainnet:
    executor: ubuntu-executor

    steps:
      - checkout

      - attach_workspace:
          at: .

      - install-scarb

      - install-voyager

      - run:
          name: Verify contract on Mainnet
          command: |
            CLASS_HASH=$(cat class_hash.txt)
            echo "Verifying class hash: $CLASS_HASH"

            voyager verify \
              --network mainnet \
              --class-hash $CLASS_HASH \
              --contract-name MyContract \
              --license MIT \
              --watch \
              --verbose

            VERIFY_EXIT=$?

            if [ $VERIFY_EXIT -eq 0 ]; then
              echo "✓ Verification successful!"
              echo "VERIFICATION_STATUS=success" >> verification_result.txt
              echo "VOYAGER_URL=https://voyager.online/class/$CLASS_HASH" >> verification_result.txt
            else
              echo "✗ Verification failed"
              echo "VERIFICATION_STATUS=failed" >> verification_result.txt
              exit 1
            fi

      - persist_to_workspace:
          root: .
          paths:
            - verification_result.txt

      - slack/notify:
          event: pass
          custom: |
            {
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "✅ *Contract Verified Successfully*\n\n*Network:* Mainnet\n*Class Hash:* `$(cat class_hash.txt)`\n\n<https://voyager.online/class/$(cat class_hash.txt)|View on Voyager>"
                  }
                }
              ]
            }

workflows:
  version: 2

  deploy-and-verify:
    jobs:
      - build

      - deploy-testnet:
          requires:
            - build
          filters:
            branches:
              only:
                - main
                - develop

      - verify-testnet:
          requires:
            - deploy-testnet

      - hold-mainnet-deploy:
          type: approval
          requires:
            - verify-testnet
          filters:
            branches:
              only: main

      - deploy-mainnet:
          requires:
            - hold-mainnet-deploy

      - verify-mainnet:
          requires:
            - deploy-mainnet
```

### Approval Workflows

CircleCI's `hold` jobs require manual approval:

```yaml
- hold-mainnet-deploy:
    type: approval
    requires:
      - verify-testnet
    filters:
      branches:
        only: main
```

This creates a pause in the workflow where a team member must click "Approve" before mainnet deployment proceeds.

## Example 4: Jenkins

Jenkins provides flexible pipeline-as-code with Groovy. This example shows a complete Jenkinsfile for verification.

### Jenkinsfile

Create `Jenkinsfile`:

```groovy
// Jenkins Pipeline for Starknet Contract Verification

pipeline {
    agent any

    environment {
        SCARB_VERSION = '2.8.4'
        VOYAGER_VERSION = '2.0.0'
        PATH = "${env.HOME}/.local/bin:${env.HOME}/.voyager/bin:${env.HOME}/.starkli/bin:${env.PATH}"
    }

    parameters {
        choice(
            name: 'NETWORK',
            choices: ['sepolia', 'mainnet'],
            description: 'Network to deploy to'
        )
        booleanParam(
            name: 'SKIP_VERIFICATION',
            defaultValue: false,
            description: 'Skip verification step'
        )
    }

    stages {
        stage('Setup') {
            steps {
                script {
                    echo "Setting up environment"
                    sh 'which curl || apt-get update && apt-get install -y curl'
                }
            }
        }

        stage('Install Dependencies') {
            parallel {
                stage('Install Scarb') {
                    steps {
                        script {
                            sh '''
                                if ! command -v scarb &> /dev/null; then
                                    curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh -s -- -v ${SCARB_VERSION}
                                fi
                                scarb --version
                            '''
                        }
                    }
                }

                stage('Install voyager-verifier') {
                    steps {
                        script {
                            sh '''
                                if ! command -v voyager &> /dev/null; then
                                    curl -L https://raw.githubusercontent.com/NethermindEth/voyager-verify/main/install.sh | bash
                                fi
                                voyager --version
                            '''
                        }
                    }
                }

                stage('Install Starkli') {
                    steps {
                        script {
                            sh '''
                                if ! command -v starkli &> /dev/null; then
                                    curl https://get.starkli.sh | sh
                                    starkliup -v 0.3.5
                                fi
                                starkli --version
                            '''
                        }
                    }
                }
            }
        }

        stage('Build Contracts') {
            steps {
                script {
                    echo "Building contracts with Scarb"
                    sh '''
                        scarb clean
                        scarb --release build
                        ls -la target/release/
                    '''
                }
            }
        }

        stage('Deploy Contract') {
            steps {
                script {
                    echo "Deploying to ${params.NETWORK}"

                    withCredentials([
                        file(credentialsId: 'starknet-account', variable: 'ACCOUNT_FILE'),
                        file(credentialsId: 'starknet-keystore', variable: 'KEYSTORE_FILE')
                    ]) {
                        sh '''
                            # Set RPC URL based on network
                            if [ "${NETWORK}" == "mainnet" ]; then
                                RPC_URL="https://starknet-mainnet.public.blastapi.io"
                            else
                                RPC_URL="https://starknet-sepolia.public.blastapi.io"
                            fi

                            # Deploy contract
                            OUTPUT=$(starkli declare \
                                target/release/my_contract_MyContract.contract_class.json \
                                --rpc $RPC_URL \
                                --account $ACCOUNT_FILE \
                                --keystore $KEYSTORE_FILE 2>&1)

                            echo "$OUTPUT"

                            # Extract class hash
                            CLASS_HASH=$(echo "$OUTPUT" | grep -oP "Class hash declared: \\K0x[0-9a-fA-F]+")

                            if [ -z "$CLASS_HASH" ]; then
                                echo "Error: Failed to extract class hash"
                                exit 1
                            fi

                            echo "Deployed class hash: $CLASS_HASH"
                            echo "$CLASS_HASH" > class_hash.txt

                            # Save deployment info
                            echo "{\\"class_hash\\":\\"$CLASS_HASH\\",\\"network\\":\\"${NETWORK}\\",\\"timestamp\\":\\"$(date -Iseconds)\\"}" > deployment.json
                        '''
                    }

                    // Archive deployment artifacts
                    archiveArtifacts artifacts: 'deployment.json,class_hash.txt', fingerprint: true

                    // Read class hash for next stage
                    env.CLASS_HASH = readFile('class_hash.txt').trim()
                    echo "CLASS_HASH=${env.CLASS_HASH}"
                }
            }
        }

        stage('Verify Contract') {
            when {
                expression { !params.SKIP_VERIFICATION }
            }

            steps {
                script {
                    echo "Verifying contract on ${params.NETWORK}"
                    echo "Class hash: ${env.CLASS_HASH}"

                    sh """
                        voyager verify \\
                            --network ${params.NETWORK} \\
                            --class-hash ${env.CLASS_HASH} \\
                            --contract-name MyContract \\
                            --license MIT \\
                            --watch \\
                            --verbose

                        VERIFY_EXIT=\$?

                        if [ \$VERIFY_EXIT -eq 0 ]; then
                            echo "✓ Verification successful!"
                            echo "View on Voyager: https://voyager.online/class/${env.CLASS_HASH}"
                            echo "success" > verification_status.txt
                        else
                            echo "✗ Verification failed with exit code \$VERIFY_EXIT"
                            echo "failed" > verification_status.txt
                            exit 1
                        fi
                    """

                    // Archive verification result
                    archiveArtifacts artifacts: 'verification_status.txt', fingerprint: true
                }
            }
        }

        stage('Generate Report') {
            steps {
                script {
                    def classHash = env.CLASS_HASH
                    def network = params.NETWORK
                    def voyagerUrl = "https://voyager.online/class/${classHash}"

                    echo """
                    ╔═══════════════════════════════════════════════════════════╗
                    ║                   Deployment Report                       ║
                    ╠═══════════════════════════════════════════════════════════╣
                    ║ Network:     ${network}
                    ║ Class Hash:  ${classHash}
                    ║ Branch:      ${env.BRANCH_NAME}
                    ║ Build:       ${env.BUILD_NUMBER}
                    ║ Status:      ✓ Verified
                    ║ Voyager URL: ${voyagerUrl}
                    ╚═══════════════════════════════════════════════════════════╝
                    """

                    // Create badge
                    sh 'mkdir -p badges'
                    sh 'echo \'{"schemaVersion": 1, "label": "contract", "message": "verified", "color": "success"}\' > badges/verification.json'

                    archiveArtifacts artifacts: 'badges/verification.json', fingerprint: true
                }
            }
        }
    }

    post {
        success {
            script {
                echo "✅ Pipeline completed successfully"

                // Send Slack notification
                slackSend(
                    color: 'good',
                    message: """
                    ✅ Contract Verified Successfully

                    Network: ${params.NETWORK}
                    Class Hash: `${env.CLASS_HASH}`
                    Branch: ${env.BRANCH_NAME}

                    <https://voyager.online/class/${env.CLASS_HASH}|View on Voyager>
                    """,
                    channel: '#deployments'
                )
            }
        }

        failure {
            script {
                echo "❌ Pipeline failed"

                // Send Slack notification
                slackSend(
                    color: 'danger',
                    message: """
                    ❌ Contract Verification Failed

                    Network: ${params.NETWORK}
                    Branch: ${env.BRANCH_NAME}
                    Build: ${env.BUILD_NUMBER}

                    <${env.BUILD_URL}|View Logs>
                    """,
                    channel: '#deployments'
                )
            }
        }

        always {
            // Clean up workspace
            cleanWs()
        }
    }
}
```

### Credential Binding

Configure credentials in Jenkins:

1. Go to **Manage Jenkins** → **Credentials**
2. Add credentials:
   - `starknet-account` - File credential with account JSON
   - `starknet-keystore` - File credential with keystore
3. Reference in pipeline with `withCredentials`

## Common Patterns

### Pattern 1: Deploy-then-Verify (Sequential)

Most straightforward approach - deploy then verify:

```yaml
# GitHub Actions
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy contract
        run: deploy_script.sh
      - name: Save class hash
        run: echo $CLASS_HASH > class_hash.txt

  verify:
    needs: deploy
    runs-on: ubuntu-latest
    steps:
      - name: Read class hash
        run: CLASS_HASH=$(cat class_hash.txt)
      - name: Verify
        run: voyager verify --class-hash $CLASS_HASH --watch
```

**Pros:**
- Simple and straightforward
- Easy to debug
- Clear separation of concerns

**Cons:**
- Slower (sequential execution)
- Blocks on verification

### Pattern 2: Parallel Verification

Verify multiple contracts simultaneously:

```yaml
# GitHub Actions
jobs:
  deploy:
    runs-on: ubuntu-latest
    outputs:
      token_hash: ${{ steps.deploy-token.outputs.hash }}
      staking_hash: ${{ steps.deploy-staking.outputs.hash }}
      governance_hash: ${{ steps.deploy-governance.outputs.hash }}
    steps:
      - name: Deploy all contracts
        run: deploy_all.sh

  verify:
    needs: deploy
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - name: Token
            hash: ${{ needs.deploy.outputs.token_hash }}
          - name: Staking
            hash: ${{ needs.deploy.outputs.staking_hash }}
          - name: Governance
            hash: ${{ needs.deploy.outputs.governance_hash }}
    steps:
      - name: Verify ${{ matrix.name }}
        run: |
          voyager verify \
            --network mainnet \
            --class-hash ${{ matrix.hash }} \
            --contract-name ${{ matrix.name }} \
            --watch
```

**Pros:**
- Faster (parallel execution)
- Efficient for multiple contracts

**Cons:**
- More complex setup
- Harder to debug failures

### Pattern 3: Conditional Verification

Only verify on specific branches or tags:

```yaml
# GitHub Actions
jobs:
  verify:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')
    steps:
      - name: Verify on main or release tags only
        run: voyager verify --watch
```

**Use cases:**
- Production deployments only
- Release tags
- Protected branches

### Pattern 4: Manual Approval

Require human approval before verification:

```yaml
# GitHub Actions (using environments)
jobs:
  verify:
    runs-on: ubuntu-latest
    environment:
      name: production
      # Configure required reviewers in repo settings
    steps:
      - name: Verify after approval
        run: voyager verify --watch
```

**Or CircleCI:**

```yaml
workflows:
  deploy:
    jobs:
      - deploy-mainnet
      - hold-verification:
          type: approval
          requires:
            - deploy-mainnet
      - verify-mainnet:
          requires:
            - hold-verification
```

## Configuration Management

### Using .voyager.toml in CI

Commit configuration to repository for consistency:

```toml
# .voyager.toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
verbose = true
notify = false  # Disable in CI
```

**In CI pipeline:**

```yaml
- name: Verify with config file
  run: |
    # Config is automatically detected
    voyager verify --class-hash $CLASS_HASH --contract-name MyContract
```

### Environment-Specific Configs

Maintain separate configs for different environments:

```bash
# Directory structure
.
├── .voyager.dev.toml      # Development config
├── .voyager.staging.toml  # Staging config
└── .voyager.prod.toml     # Production config
```

**In CI:**

```yaml
- name: Select config based on environment
  run: |
    if [ "$ENV" == "production" ]; then
      cp .voyager.prod.toml .voyager.toml
    elif [ "$ENV" == "staging" ]; then
      cp .voyager.staging.toml .voyager.toml
    else
      cp .voyager.dev.toml .voyager.toml
    fi

- name: Verify
  run: voyager verify --class-hash $CLASS_HASH --contract-name MyContract
```

### Dynamic Configuration

Generate config from deployment output:

```yaml
- name: Generate verification config
  run: |
    # Read deployment manifest
    TOKEN_HASH=$(jq -r '.contracts.token.class_hash' deployment.json)
    STAKING_HASH=$(jq -r '.contracts.staking.class_hash' deployment.json)

    # Generate .voyager.toml
    cat > .voyager.toml <<EOF
    [voyager]
    network = "mainnet"
    license = "MIT"
    watch = true

    [[contracts]]
    class-hash = "$TOKEN_HASH"
    contract-name = "Token"

    [[contracts]]
    class-hash = "$STAKING_HASH"
    contract-name = "Staking"
    EOF

- name: Batch verify
  run: voyager verify
```

## Secrets Management

### GitHub Secrets

**Configure:**
1. Repository Settings → Secrets and variables → Actions
2. Add secrets:
   - `STARKNET_ACCOUNT`
   - `STARKNET_KEYSTORE`
   - `SLACK_WEBHOOK_URL`

**Use:**

```yaml
- name: Verify contract
  env:
    ACCOUNT: ${{ secrets.STARKNET_ACCOUNT }}
    KEYSTORE: ${{ secrets.STARKNET_KEYSTORE }}
  run: |
    echo "$ACCOUNT" > account.json
    echo "$KEYSTORE" > keystore.json
    # Use in deployment/verification
```

### GitLab CI Variables

**Configure:**
Settings → CI/CD → Variables

**Types:**
- **Protected**: Only available on protected branches
- **Masked**: Hidden in logs
- **File**: Stored as file (use for JSON configs)

**Use:**

```yaml
verify:
  script:
    - echo "Using protected variable: $STARKNET_ACCOUNT_FILE"
    - voyager verify --class-hash $CLASS_HASH --watch
```

### Environment Variables Best Practices

1. **Never commit secrets** to version control
2. **Use file-type secrets** for JSON configs
3. **Mark secrets as protected** for production
4. **Rotate secrets regularly**
5. **Use different secrets** for different environments
6. **Audit secret usage** in logs

## Error Handling

### Verification Failures in CI

Handle verification failures gracefully:

```yaml
- name: Verify contract
  id: verify
  continue-on-error: true
  run: |
    voyager verify \
      --network mainnet \
      --class-hash $CLASS_HASH \
      --contract-name MyContract \
      --watch \
      --verbose

- name: Handle failure
  if: steps.verify.outcome == 'failure'
  run: |
    echo "❌ Verification failed!"
    echo "Check logs above for details"

    # Send notification
    curl -X POST $SLACK_WEBHOOK \
      -H 'Content-Type: application/json' \
      -d '{"text":"Verification failed for '$CLASS_HASH'"}'

    # Fail the build
    exit 1
```

### Timeout Handling

Set appropriate timeouts for verification:

```yaml
- name: Verify with timeout
  timeout-minutes: 10
  run: |
    voyager verify \
      --network mainnet \
      --class-hash $CLASS_HASH \
      --contract-name MyContract \
      --watch
```

**Recommended timeouts:**
- Simple contracts: 5-10 minutes
- Complex contracts: 10-15 minutes
- Batch verification: 15-30 minutes

### Retry Logic

Implement retries for transient failures:

```yaml
- name: Verify with retry
  uses: nick-invision/retry@v2
  with:
    timeout_minutes: 10
    max_attempts: 3
    retry_wait_seconds: 60
    command: |
      voyager verify \
        --network mainnet \
        --class-hash $CLASS_HASH \
        --contract-name MyContract \
        --watch
```

**Or in shell script:**

```bash
#!/bin/bash
MAX_ATTEMPTS=3
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
  echo "Verification attempt $ATTEMPT of $MAX_ATTEMPTS"

  if voyager verify --network mainnet --class-hash $CLASS_HASH --contract-name MyContract --watch; then
    echo "✓ Verification successful"
    exit 0
  else
    echo "✗ Attempt $ATTEMPT failed"
    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
      echo "Retrying in 60 seconds..."
      sleep 60
    fi
    ATTEMPT=$((ATTEMPT + 1))
  fi
done

echo "❌ Verification failed after $MAX_ATTEMPTS attempts"
exit 1
```

### Notification Strategies

**Slack Notifications:**

```yaml
- name: Notify Slack on success
  if: success()
  run: |
    curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
      -H 'Content-Type: application/json' \
      -d '{
        "text": "✅ Contract verified successfully",
        "blocks": [{
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*Contract Verified*\n\nClass Hash: `'$CLASS_HASH'`\nNetwork: mainnet\n\n<https://voyager.online/class/'$CLASS_HASH'|View on Voyager>"
          }
        }]
      }'

- name: Notify Slack on failure
  if: failure()
  run: |
    curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
      -H 'Content-Type: application/json' \
      -d '{
        "text": "❌ Contract verification failed",
        "blocks": [{
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*Verification Failed*\n\nBranch: '${{ github.ref_name }}'\n\n<'${{ github.server_url }}'/'${{ github.repository }}'/actions/runs/'${{ github.run_id }}'|View Logs>"
          }
        }]
      }'
```

**Email Notifications:**

```yaml
- name: Send email notification
  if: always()
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.gmail.com
    server_port: 465
    username: ${{ secrets.EMAIL_USERNAME }}
    password: ${{ secrets.EMAIL_PASSWORD }}
    subject: "Contract Verification: ${{ job.status }}"
    to: team@example.com
    from: ci@example.com
    body: |
      Verification Status: ${{ job.status }}
      Network: mainnet
      Class Hash: ${{ env.CLASS_HASH }}
      Branch: ${{ github.ref_name }}

      View on Voyager: https://voyager.online/class/${{ env.CLASS_HASH }}
```

## Best Practices

### 1. Always Verify in CI

**Automate verification** - Don't rely on manual steps:

```yaml
# ✓ Good - automated
- name: Verify automatically after deploy
  run: voyager verify --class-hash $CLASS_HASH --watch

# ✗ Bad - manual step
# "Remember to verify the contract on Voyager website"
```

### 2. Use --watch in CI

**Wait for completion** - Don't submit and forget:

```bash
# ✓ Good - waits for result
voyager verify --network mainnet --class-hash $HASH --watch

# ✗ Bad - doesn't wait
voyager verify --network mainnet --class-hash $HASH
```

### 3. Set Reasonable Timeouts

**Account for network delays** - Verification can take several minutes:

```yaml
- name: Verify with timeout
  timeout-minutes: 10  # ✓ Good
  run: voyager verify --watch
```

### 4. Fail the Build on Verification Failure

**Make verification a quality gate**:

```yaml
- name: Verify contract
  run: |
    voyager verify --watch

    # Exit with error if verification failed
    if [ $? -ne 0 ]; then
      echo "❌ Verification failed - failing build"
      exit 1
    fi
```

### 5. Use Configuration Files

**Don't hardcode in workflows**:

```toml
# .voyager.toml - committed to repo
[voyager]
network = "mainnet"
license = "MIT"
watch = true
verbose = true
```

```yaml
# Workflow uses config file
- name: Verify
  run: voyager verify --class-hash $CLASS_HASH --contract-name MyContract
```

### 6. Manage Secrets Properly

**Never commit sensitive data**:

```yaml
# ✓ Good - using secrets
env:
  ACCOUNT: ${{ secrets.STARKNET_ACCOUNT }}

# ✗ Bad - hardcoded
env:
  ACCOUNT: '{"version":1,"private_key":"0x..."}'
```

### 7. Cache Dependencies

**Speed up CI runs**:

```yaml
- name: Cache Scarb
  uses: actions/cache@v4
  with:
    path: |
      ~/.cargo
      target/
    key: scarb-${{ hashFiles('Scarb.toml') }}
```

### 8. Test Verification on Testnet First

**Catch issues early**:

```yaml
jobs:
  test-testnet:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to sepolia
        run: deploy_sepolia.sh
      - name: Verify on sepolia
        run: voyager verify --network sepolia --watch

  deploy-mainnet:
    needs: test-testnet  # Only proceed if testnet succeeds
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to mainnet
        run: deploy_mainnet.sh
      - name: Verify on mainnet
        run: voyager verify --network mainnet --watch
```

### 9. Tag Releases with Verification Status

**Track what's verified**:

```yaml
- name: Tag release
  if: success()
  run: |
    git tag -a "v$VERSION-verified" -m "Verified on Voyager: $CLASS_HASH"
    git push --tags
```

### 10. Send Notifications

**Alert team of verification status**:

```yaml
- name: Notify team
  if: always()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Verification ${{ job.status }}: ${{ env.CLASS_HASH }}"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## Debugging CI Verification

### Common Issues

**Issue 1: Permission Errors**

```
Error: Permission denied when accessing deployment files
```

**Solution:**

```yaml
- name: Fix permissions
  run: |
    chmod +x deploy.sh
    chmod 600 keystore.json
```

**Issue 2: Network Timeouts**

```
Error: Request timeout while verifying
```

**Solution:**

```yaml
- name: Increase timeout
  timeout-minutes: 15
  run: voyager verify --watch
```

**Issue 3: Missing Dependencies**

```
Error: scarb: command not found
```

**Solution:**

```yaml
- name: Install Scarb
  run: |
    curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
    echo "$HOME/.local/bin" >> $GITHUB_PATH
```

**Issue 4: Configuration Errors**

```
Error: No contracts defined in .voyager.toml
```

**Solution:**

```yaml
- name: Validate config
  run: |
    if [ ! -f .voyager.toml ]; then
      echo "Error: .voyager.toml not found"
      exit 1
    fi
    cat .voyager.toml  # Print for debugging
```

### Using --verbose in CI

**Capture detailed logs**:

```yaml
- name: Verify with verbose output
  run: |
    voyager verify \
      --network mainnet \
      --class-hash $CLASS_HASH \
      --contract-name MyContract \
      --watch \
      --verbose 2>&1 | tee verification.log

- name: Upload logs
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: verification-logs
    path: verification.log
```

### Artifact Collection

**Save verification results**:

```yaml
- name: Verify and save results
  run: |
    voyager verify --watch > verification_output.txt 2>&1
    echo $? > exit_code.txt

- name: Upload verification artifacts
  uses: actions/upload-artifact@v4
  with:
    name: verification-results
    path: |
      verification_output.txt
      exit_code.txt
      deployment.json
    retention-days: 30
```

## Complete Example: Full GitHub Actions Workflow

Here's a complete, production-ready GitHub Actions workflow demonstrating all concepts:

```yaml
name: Production Deploy and Verify

on:
  push:
    branches: [main, production]
    tags: ['v*']
  pull_request:
    branches: [main]
  workflow_dispatch:

env:
  SCARB_VERSION: '2.8.4'
  VOYAGER_VERSION: '2.0.0'

jobs:
  build:
    name: Build Contracts
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Scarb
        uses: software-mansion/setup-scarb@v1
        with:
          scarb-version: ${{ env.SCARB_VERSION }}

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo
            target/
          key: scarb-${{ hashFiles('Scarb.toml') }}

      - name: Build
        run: scarb --release build

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: contracts
          path: target/release/*.json

  deploy-testnet:
    name: Deploy to Testnet
    needs: build
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    environment: testnet

    outputs:
      token_hash: ${{ steps.deploy.outputs.token_hash }}
      staking_hash: ${{ steps.deploy.outputs.staking_hash }}
      governance_hash: ${{ steps.deploy.outputs.governance_hash }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Download artifacts
        uses: actions/download-artifact@v4
        with:
          name: contracts
          path: target/release/

      - name: Setup Starkli
        run: |
          curl https://get.starkli.sh | sh
          echo "$HOME/.starkli/bin" >> $GITHUB_PATH
          starkliup

      - name: Deploy contracts
        id: deploy
        env:
          ACCOUNT: ${{ secrets.SEPOLIA_ACCOUNT }}
          KEYSTORE: ${{ secrets.SEPOLIA_KEYSTORE }}
        run: |
          # Deploy Token
          TOKEN_OUTPUT=$(starkli declare target/release/token_Token.contract_class.json --rpc https://starknet-sepolia.public.blastapi.io 2>&1)
          TOKEN_HASH=$(echo "$TOKEN_OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
          echo "token_hash=$TOKEN_HASH" >> $GITHUB_OUTPUT

          # Deploy Staking
          STAKING_OUTPUT=$(starkli declare target/release/staking_Staking.contract_class.json --rpc https://starknet-sepolia.public.blastapi.io 2>&1)
          STAKING_HASH=$(echo "$STAKING_OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
          echo "staking_hash=$STAKING_HASH" >> $GITHUB_OUTPUT

          # Deploy Governance
          GOV_OUTPUT=$(starkli declare target/release/governance_Governance.contract_class.json --rpc https://starknet-sepolia.public.blastapi.io 2>&1)
          GOV_HASH=$(echo "$GOV_OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
          echo "governance_hash=$GOV_HASH" >> $GITHUB_OUTPUT

  verify-testnet:
    name: Verify on Testnet
    needs: deploy-testnet
    runs-on: ubuntu-latest

    strategy:
      matrix:
        contract:
          - name: Token
            hash_var: token_hash
          - name: Staking
            hash_var: staking_hash
          - name: Governance
            hash_var: governance_hash

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Scarb
        uses: software-mansion/setup-scarb@v1
        with:
          scarb-version: ${{ env.SCARB_VERSION }}

      - name: Install voyager-verifier
        run: |
          curl -L https://raw.githubusercontent.com/NethermindEth/voyager-verify/main/install.sh | bash
          echo "$HOME/.voyager/bin" >> $GITHUB_PATH

      - name: Verify ${{ matrix.contract.name }}
        timeout-minutes: 10
        run: |
          HASH="${{ needs.deploy-testnet.outputs[matrix.contract.hash_var] }}"

          voyager verify \
            --network sepolia \
            --class-hash $HASH \
            --contract-name ${{ matrix.contract.name }} \
            --license MIT \
            --watch \
            --verbose

      - name: Comment on PR
        uses: actions/github-script@v7
        with:
          script: |
            const hash = '${{ needs.deploy-testnet.outputs[matrix.contract.hash_var] }}';
            const name = '${{ matrix.contract.name }}';

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `✅ **${name}** verified on Sepolia\n\nClass Hash: \`${hash}\`\n\n[View on Voyager](https://sepolia.voyager.online/class/${hash})`
            });

  deploy-mainnet:
    name: Deploy to Mainnet
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')
    environment: production

    outputs:
      token_hash: ${{ steps.deploy.outputs.token_hash }}
      staking_hash: ${{ steps.deploy.outputs.staking_hash }}
      governance_hash: ${{ steps.deploy.outputs.governance_hash }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Download artifacts
        uses: actions/download-artifact@v4
        with:
          name: contracts
          path: target/release/

      - name: Setup Starkli
        run: |
          curl https://get.starkli.sh | sh
          echo "$HOME/.starkli/bin" >> $GITHUB_PATH
          starkliup

      - name: Deploy contracts
        id: deploy
        env:
          ACCOUNT: ${{ secrets.MAINNET_ACCOUNT }}
          KEYSTORE: ${{ secrets.MAINNET_KEYSTORE }}
        run: |
          # Deploy all contracts and capture hashes
          # (Same as testnet but with mainnet RPC)
          TOKEN_OUTPUT=$(starkli declare target/release/token_Token.contract_class.json --rpc https://starknet-mainnet.public.blastapi.io 2>&1)
          TOKEN_HASH=$(echo "$TOKEN_OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
          echo "token_hash=$TOKEN_HASH" >> $GITHUB_OUTPUT

          STAKING_OUTPUT=$(starkli declare target/release/staking_Staking.contract_class.json --rpc https://starknet-mainnet.public.blastapi.io 2>&1)
          STAKING_HASH=$(echo "$STAKING_OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
          echo "staking_hash=$STAKING_HASH" >> $GITHUB_OUTPUT

          GOV_OUTPUT=$(starkli declare target/release/governance_Governance.contract_class.json --rpc https://starknet-mainnet.public.blastapi.io 2>&1)
          GOV_HASH=$(echo "$GOV_OUTPUT" | grep -oP "Class hash declared: \K0x[0-9a-fA-F]+")
          echo "governance_hash=$GOV_HASH" >> $GITHUB_OUTPUT

  verify-mainnet:
    name: Verify on Mainnet
    needs: deploy-mainnet
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Scarb
        uses: software-mansion/setup-scarb@v1
        with:
          scarb-version: ${{ env.SCARB_VERSION }}

      - name: Install voyager-verifier
        run: |
          curl -L https://raw.githubusercontent.com/NethermindEth/voyager-verify/main/install.sh | bash
          echo "$HOME/.voyager/bin" >> $GITHUB_PATH

      - name: Create batch config
        run: |
          cat > .voyager.toml <<EOF
          [voyager]
          network = "mainnet"
          license = "MIT"
          watch = true
          verbose = true

          [[contracts]]
          class-hash = "${{ needs.deploy-mainnet.outputs.token_hash }}"
          contract-name = "Token"

          [[contracts]]
          class-hash = "${{ needs.deploy-mainnet.outputs.staking_hash }}"
          contract-name = "Staking"

          [[contracts]]
          class-hash = "${{ needs.deploy-mainnet.outputs.governance_hash }}"
          contract-name = "Governance"
          EOF

      - name: Batch verify
        timeout-minutes: 30
        run: |
          voyager verify --batch-delay 5

      - name: Upload verification results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: verification-results
          path: .voyager.toml

  notify:
    name: Send Notifications
    needs: [deploy-mainnet, verify-mainnet]
    runs-on: ubuntu-latest
    if: always()

    steps:
      - name: Notify success
        if: needs.verify-mainnet.result == 'success'
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "✅ Mainnet deployment verified",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Deployment Complete*\n\n• Token: `${{ needs.deploy-mainnet.outputs.token_hash }}`\n• Staking: `${{ needs.deploy-mainnet.outputs.staking_hash }}`\n• Governance: `${{ needs.deploy-mainnet.outputs.governance_hash }}`\n\nAll contracts verified on Voyager"
                }
              }]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}

      - name: Notify failure
        if: needs.verify-mainnet.result == 'failure'
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "❌ Verification failed",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Verification Failed*\n\nBranch: ${{ github.ref_name }}\n\n<${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Logs>"
                }
              }]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Expected Output from Full Workflow

**Build Stage:**
```
Run scarb --release build
   Compiling my_contracts v1.0.0 (~/project/Scarb.toml)
    Finished release target(s) in 5 seconds

✓ Build completed
```

**Deploy Stage:**
```
Run starkli declare target/release/token_Token.contract_class.json
Declaring contract class...
Class hash declared: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

✓ All contracts deployed
```

**Verify Stage:**
```
Starting batch verification for 3 contracts...

[1/3] Verifying: Token
  ✓ Files collected: 5 files
  ✓ Project built successfully
  ✓ Verification job submitted (Job ID: abc-123)

[2/3] Verifying: Staking
  ✓ Using cached build
  ✓ Verification job submitted (Job ID: def-456)

[3/3] Verifying: Governance
  ✓ Using cached build
  ✓ Verification job submitted (Job ID: ghi-789)

⏳ Watching 3 verification job(s)...
  ✓ 3 Succeeded | ⏳ 0 Pending | ✗ 0 Failed

✓ All verifications completed successfully!

════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  3
Succeeded:        3
Failed:           0
════════════════════════════════════════
```

## Security Considerations

### API Keys & Secrets

**Best practices:**

1. **Never commit secrets** to repository
2. **Use repository secrets** for sensitive data
3. **Rotate secrets regularly**
4. **Limit secret access** to necessary jobs
5. **Audit secret usage** in workflow logs

**Example:**

```yaml
# ✓ Good
env:
  ACCOUNT: ${{ secrets.STARKNET_ACCOUNT }}

# ✗ Bad
env:
  ACCOUNT: '{"private_key":"0x123..."}'
```

### Network Selection

**Testnet vs Mainnet:**

```yaml
# Deploy to testnet for testing
- name: Deploy testnet
  if: github.event_name == 'pull_request'
  run: deploy.sh --network sepolia

# Deploy to mainnet only on main branch
- name: Deploy mainnet
  if: github.ref == 'refs/heads/main'
  environment: production  # Requires approval
  run: deploy.sh --network mainnet
```

### Class Hash Validation

**Ensure correctness:**

```yaml
- name: Validate class hash
  run: |
    if [[ ! $CLASS_HASH =~ ^0x[0-9a-fA-F]{64}$ ]]; then
      echo "Error: Invalid class hash format: $CLASS_HASH"
      exit 1
    fi

    echo "✓ Class hash validated: $CLASS_HASH"
```

## Advanced Patterns

### Multi-Environment Deployment

Deploy through dev → staging → production:

```yaml
jobs:
  deploy-dev:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    steps:
      - name: Deploy to dev
        run: deploy.sh --network sepolia --env dev
      - name: Verify dev
        run: voyager verify --network sepolia --watch

  deploy-staging:
    needs: deploy-dev
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: staging
    steps:
      - name: Deploy to staging
        run: deploy.sh --network sepolia --env staging
      - name: Verify staging
        run: voyager verify --network sepolia --watch

  deploy-production:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment: production  # Requires approval
    steps:
      - name: Deploy to production
        run: deploy.sh --network mainnet
      - name: Verify production
        run: voyager verify --network mainnet --watch
```

### Approval Gates

Require manual approval for critical steps:

```yaml
# GitHub Actions (using environments)
deploy-mainnet:
  runs-on: ubuntu-latest
  environment:
    name: production
    # Configure required reviewers in repo settings

# CircleCI
workflows:
  deploy:
    jobs:
      - hold-approval:
          type: approval
      - deploy-mainnet:
          requires:
            - hold-approval
```

### Rollback on Failure

Handle verification failures with rollback:

```yaml
- name: Verify deployment
  id: verify
  run: voyager verify --watch

- name: Rollback on failure
  if: steps.verify.outcome == 'failure'
  run: |
    echo "❌ Verification failed - rolling back"
    ./rollback.sh --to-previous-version
    exit 1
```

### Integration Testing

Verify after deployment tests pass:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: deploy.sh

  integration-tests:
    needs: deploy
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: pytest tests/integration/

  verify:
    needs: integration-tests  # Only verify if tests pass
    runs-on: ubuntu-latest
    steps:
      - name: Verify
        run: voyager verify --watch
```

## Monitoring & Reporting

### CI Status Badges

Add verification status to README:

**GitHub Actions:**

```markdown
[![Verification Status](https://github.com/username/repo/actions/workflows/verify.yml/badge.svg)](https://github.com/username/repo/actions/workflows/verify.yml)
```

**GitLab CI:**

```markdown
[![Pipeline Status](https://gitlab.com/username/repo/badges/main/pipeline.svg)](https://gitlab.com/username/repo/-/pipelines)
```

**CircleCI:**

```markdown
[![CircleCI](https://circleci.com/gh/username/repo.svg?style=svg)](https://circleci.com/gh/username/repo)
```

### Notification Integration

**Slack Integration:**

```yaml
- name: Notify Slack
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Verification complete",
        "attachments": [{
          "color": "good",
          "fields": [
            {"title": "Network", "value": "mainnet", "short": true},
            {"title": "Status", "value": "✓ Verified", "short": true},
            {"title": "Class Hash", "value": "'$CLASS_HASH'"}
          ]
        }]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

**Discord Integration:**

```yaml
- name: Notify Discord
  run: |
    curl -X POST "${{ secrets.DISCORD_WEBHOOK_URL }}" \
      -H "Content-Type: application/json" \
      -d '{
        "content": "✅ Contract verified",
        "embeds": [{
          "title": "Verification Complete",
          "description": "Class Hash: `'$CLASS_HASH'`",
          "color": 65280,
          "url": "https://voyager.online/class/'$CLASS_HASH'"
        }]
      }'
```

**Email Notifications:**

```yaml
- name: Send email
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.gmail.com
    server_port: 465
    username: ${{ secrets.EMAIL_USERNAME }}
    password: ${{ secrets.EMAIL_PASSWORD }}
    subject: "Verification Status: ${{ job.status }}"
    to: team@example.com
    from: ci@example.com
    body: |
      Verification completed with status: ${{ job.status }}

      Network: mainnet
      Class Hash: ${{ env.CLASS_HASH }}

      View: https://voyager.online/class/${{ env.CLASS_HASH }}
```

### Verification History

Track verifications across deployments:

```yaml
- name: Record verification
  run: |
    # Use voyager history commands
    voyager history list --limit 10 > verification_history.txt
    voyager history stats > verification_stats.txt

- name: Upload history
  uses: actions/upload-artifact@v4
  with:
    name: verification-history
    path: |
      verification_history.txt
      verification_stats.txt
```

## Next Steps

Congratulations! You've learned how to integrate voyager-verifier into CI/CD pipelines. Here's what to explore next:

1. **[Configuration Reference](../configuration/config-file.md)** - Deep dive into configuration options
2. **[History Management](../commands/history.md)** - Track verification history
3. **[Batch Verification](./multi-contract.md)** - Verify multiple contracts efficiently
4. **[Troubleshooting Guide](../troubleshooting/README.md)** - Resolve common issues
5. **[Advanced Features](../advanced/README.md)** - Desktop notifications, custom workflows

## Additional Resources

- **[GitHub Actions Documentation](https://docs.github.com/en/actions)** - GitHub Actions reference
- **[GitLab CI Documentation](https://docs.gitlab.com/ee/ci/)** - GitLab CI/CD guide
- **[CircleCI Documentation](https://circleci.com/docs/)** - CircleCI configuration
- **[Jenkins Pipeline](https://www.jenkins.io/doc/book/pipeline/)** - Jenkins pipeline syntax
- **[Starkli Documentation](https://book.starkli.rs/)** - Starknet CLI tool
- **[Scarb Documentation](https://docs.swmansion.com/scarb/)** - Cairo package manager

## Conclusion

Automating contract verification in CI/CD pipelines ensures:

- **Consistency** - Every deployment is verified the same way
- **Reliability** - No forgotten manual steps
- **Transparency** - Team visibility into verification status
- **Quality** - Verification as a required quality gate
- **Efficiency** - Save time with automation

Start with a simple deployment → verification workflow, then gradually add features like batch verification, notifications, and approval gates as your needs grow.

---

**Ready for advanced features?** Continue to [Advanced Configuration](../advanced/README.md) or [Troubleshooting Guide](../troubleshooting/README.md).
