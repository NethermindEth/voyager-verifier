# CI/CD Integration

Integrate voyager-verifier into your Continuous Integration and Deployment pipelines to automatically verify contracts when they're deployed to Starknet networks.

## Overview

Automated contract verification in CI/CD:
- Ensures deployed contracts are always verified
- Prevents manual verification steps
- Provides verification status in deployment logs
- Enables deployment gates based on verification success
- Integrates with existing workflows

## General Integration Pattern

All CI/CD integrations follow a similar pattern:

1. **Install** voyager-verifier
2. **Build** your contract with Scarb
3. **Deploy** contract to Starknet (get class hash)
4. **Verify** using voyager-verifier
5. **Check** verification status
6. **Report** results

## Installation in CI

### Using Cargo

The most reliable method across platforms:

```bash
cargo install voyager-verifier
```

### Caching for Faster Builds

Cache the installation to speed up subsequent runs:

**GitHub Actions:**
```yaml
- name: Cache cargo binaries
  uses: actions/cache@v3
  with:
    path: ~/.cargo/bin
    key: ${{ runner.os }}-cargo-bin-voyager-${{ hashFiles('**/Cargo.lock') }}
```

**GitLab CI:**
```yaml
cache:
  paths:
    - ~/.cargo/bin/voyager
```

## GitHub Actions

### Basic Workflow

```yaml
name: Deploy and Verify Contract

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy-and-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Scarb
        uses: software-mansion/setup-scarb@v1

      - name: Build Contract
        run: scarb build

      - name: Install voyager-verifier
        run: cargo install voyager-verifier

      - name: Deploy Contract
        id: deploy
        run: |
          # Your deployment script here
          # This should output the class hash
          CLASS_HASH=$(starkli declare target/release/my_contract.sierra.json)
          echo "class_hash=$CLASS_HASH" >> $GITHUB_OUTPUT

      - name: Verify Contract
        run: |
          voyager verify \
            --network mainnet \
            --class-hash ${{ steps.deploy.outputs.class_hash }} \
            --contract-name MyContract \
            --watch \
            --format json > verification-result.json

      - name: Check Verification Result
        run: |
          if [ $(jq -r '.has_failed' verification-result.json) = "true" ]; then
            echo "❌ Contract verification failed"
            jq '.' verification-result.json
            exit 1
          fi
          echo "✅ Contract verified successfully"
          jq '.class_hash' verification-result.json
```

### Advanced Workflow with Multiple Environments

```yaml
name: Multi-Environment Deployment

on:
  push:
    branches: [main, staging, develop]

env:
  CARGO_TERM_COLOR: always

jobs:
  determine-environment:
    runs-on: ubuntu-latest
    outputs:
      environment: ${{ steps.set-env.outputs.environment }}
      network: ${{ steps.set-env.outputs.network }}
    steps:
      - id: set-env
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "environment=production" >> $GITHUB_OUTPUT
            echo "network=mainnet" >> $GITHUB_OUTPUT
          elif [[ "${{ github.ref }}" == "refs/heads/staging" ]]; then
            echo "environment=staging" >> $GITHUB_OUTPUT
            echo "network=sepolia" >> $GITHUB_OUTPUT
          else
            echo "environment=development" >> $GITHUB_OUTPUT
            echo "network=sepolia" >> $GITHUB_OUTPUT
          fi

  deploy-and-verify:
    needs: determine-environment
    runs-on: ubuntu-latest
    environment: ${{ needs.determine-environment.outputs.environment }}
    steps:
      - uses: actions/checkout@v3

      - name: Cache cargo installation
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/bin/voyager
            ~/.cargo/bin/scarb
          key: ${{ runner.os }}-cargo-tools-${{ hashFiles('**/Cargo.lock') }}

      - name: Install Scarb
        uses: software-mansion/setup-scarb@v1

      - name: Build Contract
        run: scarb build --release

      - name: Install voyager-verifier
        run: |
          if ! command -v voyager &> /dev/null; then
            cargo install voyager-verifier
          fi

      - name: Deploy Contract
        id: deploy
        env:
          NETWORK: ${{ needs.determine-environment.outputs.network }}
          PRIVATE_KEY: ${{ secrets.STARKNET_PRIVATE_KEY }}
        run: |
          # Deploy using starkli or your preferred tool
          CLASS_HASH=$(./scripts/deploy.sh $NETWORK)
          echo "class_hash=$CLASS_HASH" >> $GITHUB_OUTPUT

      - name: Verify Contract
        env:
          NETWORK: ${{ needs.determine-environment.outputs.network }}
          CLASS_HASH: ${{ steps.deploy.outputs.class_hash }}
        run: |
          voyager verify \
            --network $NETWORK \
            --class-hash $CLASS_HASH \
            --contract-name MyContract \
            --lock-file \
            --watch \
            --format json \
            --verbose > verification-result.json

      - name: Parse Verification Result
        id: verify
        run: |
          IS_COMPLETED=$(jq -r '.is_completed' verification-result.json)
          HAS_FAILED=$(jq -r '.has_failed' verification-result.json)
          JOB_ID=$(jq -r '.job_id' verification-result.json)

          echo "is_completed=$IS_COMPLETED" >> $GITHUB_OUTPUT
          echo "has_failed=$HAS_FAILED" >> $GITHUB_OUTPUT
          echo "job_id=$JOB_ID" >> $GITHUB_OUTPUT

      - name: Report Verification Status
        run: |
          if [ "${{ steps.verify.outputs.has_failed }}" = "true" ]; then
            echo "::error::Contract verification failed"
            jq '.' verification-result.json
            exit 1
          fi

          echo "::notice::Contract verified successfully!"
          echo "Class Hash: ${{ steps.deploy.outputs.class_hash }}"
          echo "Job ID: ${{ steps.verify.outputs.job_id }}"

      - name: Upload Verification Result
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: verification-result-${{ needs.determine-environment.outputs.environment }}
          path: verification-result.json

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const result = JSON.parse(fs.readFileSync('verification-result.json', 'utf8'));

            const comment = result.has_failed
              ? `❌ Contract verification failed\\n\`\`\`json\\n${JSON.stringify(result, null, 2)}\\n\`\`\``
              : `✅ Contract verified successfully!\\n- Class Hash: \`${result.class_hash}\`\\n- Network: \`${{ needs.determine-environment.outputs.network }}\``;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.name,
              body: comment
            });
```

### Batch Verification Workflow

```yaml
name: Batch Contract Verification

on:
  workflow_dispatch:
    inputs:
      network:
        description: 'Network to verify on'
        required: true
        type: choice
        options:
          - mainnet
          - sepolia

jobs:
  verify-batch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install voyager-verifier
        run: cargo install voyager-verifier

      - name: Verify All Contracts
        env:
          NETWORK: ${{ inputs.network }}
        run: |
          # .voyager.toml contains [[contracts]] array
          voyager verify \
            --network $NETWORK \
            --watch \
            --batch-delay 5 \
            --format json > batch-result.json

      - name: Check Batch Results
        run: |
          FAILED=$(jq '[.results[] | select(.has_failed == true)] | length' batch-result.json)

          if [ "$FAILED" -gt 0 ]; then
            echo "::error::$FAILED contract(s) failed verification"
            jq '.results[] | select(.has_failed == true)' batch-result.json
            exit 1
          fi

          echo "::notice::All contracts verified successfully"

      - name: Generate Summary
        run: |
          echo "# Batch Verification Summary" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          jq -r '.results[] | "- \(.contract_name): \(.status)"' batch-result.json >> $GITHUB_STEP_SUMMARY
```

## GitLab CI

### Basic Pipeline

```yaml
stages:
  - build
  - deploy
  - verify

variables:
  CARGO_HOME: $CI_PROJECT_DIR/.cargo

cache:
  paths:
    - .cargo/bin
    - target/

build:
  stage: build
  image: rust:latest
  script:
    - curl -L https://raw.githubusercontent.com/software-mansion/scarb/main/install.sh | bash
    - export PATH="$HOME/.local/bin:$PATH"
    - scarb build --release
  artifacts:
    paths:
      - target/release/
    expire_in: 1 hour

deploy:
  stage: deploy
  image: rust:latest
  script:
    - ./scripts/deploy.sh $CI_COMMIT_REF_NAME
  artifacts:
    reports:
      dotenv: deploy.env
  only:
    - main
    - staging

verify:
  stage: verify
  image: rust:latest
  dependencies:
    - deploy
  script:
    - cargo install voyager-verifier

    - |
      voyager verify \
        --network ${NETWORK} \
        --class-hash ${CLASS_HASH} \
        --contract-name ${CONTRACT_NAME} \
        --lock-file \
        --watch \
        --format json > verification.json

    - |
      if [ $(jq -r '.has_failed' verification.json) = "true" ]; then
        echo "Contract verification failed"
        cat verification.json
        exit 1
      fi

    - echo "Contract verified successfully"
    - jq '.class_hash' verification.json
  artifacts:
    paths:
      - verification.json
    reports:
      junit: verification.json
  only:
    - main
    - staging
```

### Multi-Environment Pipeline

```yaml
stages:
  - build
  - deploy
  - verify
  - report

.verify_template: &verify_template
  stage: verify
  image: rust:latest
  script:
    - cargo install voyager-verifier
    - |
      voyager verify \
        --network $NETWORK \
        --class-hash $CLASS_HASH \
        --contract-name $CONTRACT_NAME \
        --watch \
        --format json > verification-$CI_ENVIRONMENT_NAME.json
    - |
      if [ $(jq -r '.has_failed' verification-$CI_ENVIRONMENT_NAME.json) = "true" ]; then
        echo "Verification failed on $CI_ENVIRONMENT_NAME"
        exit 1
      fi
  artifacts:
    paths:
      - verification-*.json

verify:production:
  <<: *verify_template
  environment:
    name: production
  variables:
    NETWORK: mainnet
  dependencies:
    - deploy:production
  only:
    - main

verify:staging:
  <<: *verify_template
  environment:
    name: staging
  variables:
    NETWORK: sepolia
  dependencies:
    - deploy:staging
  only:
    - staging

report:
  stage: report
  image: alpine:latest
  script:
    - apk add --no-cache jq
    - |
      for file in verification-*.json; do
        ENV=$(echo $file | sed 's/verification-\(.*\)\.json/\1/')
        STATUS=$(jq -r '.status' $file)
        echo "$ENV: $STATUS"
      done
  when: always
```

## Jenkins

### Declarative Pipeline

```groovy
pipeline {
    agent any

    environment {
        NETWORK = 'mainnet'
        CONTRACT_NAME = 'MyContract'
        CLASS_HASH = credentials('starknet-class-hash')
    }

    stages {
        stage('Install Tools') {
            steps {
                sh '''
                    # Install Scarb
                    curl -L https://raw.githubusercontent.com/software-mansion/scarb/main/install.sh | bash
                    export PATH="$HOME/.local/bin:$PATH"

                    # Install voyager-verifier
                    cargo install voyager-verifier
                '''
            }
        }

        stage('Build Contract') {
            steps {
                sh '''
                    export PATH="$HOME/.local/bin:$PATH"
                    scarb build --release
                '''
            }
        }

        stage('Deploy Contract') {
            steps {
                script {
                    env.CLASS_HASH = sh(
                        script: './scripts/deploy.sh',
                        returnStdout: true
                    ).trim()
                }
            }
        }

        stage('Verify Contract') {
            steps {
                sh '''
                    voyager verify \
                      --network ${NETWORK} \
                      --class-hash ${CLASS_HASH} \
                      --contract-name ${CONTRACT_NAME} \
                      --watch \
                      --format json > verification-result.json
                '''
            }
        }

        stage('Check Verification') {
            steps {
                script {
                    def result = readJSON file: 'verification-result.json'

                    if (result.has_failed) {
                        error("Contract verification failed: ${result.message}")
                    }

                    echo "✅ Contract verified successfully!"
                    echo "Class Hash: ${result.class_hash}"
                    echo "Job ID: ${result.job_id}"
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'verification-result.json', allowEmptyArchive: true
        }
        success {
            echo 'Deployment and verification completed successfully'
        }
        failure {
            echo 'Deployment or verification failed'
        }
    }
}
```

### Scripted Pipeline with Parallel Verification

```groovy
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Install Dependencies') {
        sh 'cargo install voyager-verifier'
    }

    stage('Build Contracts') {
        sh 'scarb build --release'
    }

    stage('Deploy and Verify') {
        def contracts = [
            [name: 'TokenContract', classHash: env.TOKEN_CLASS_HASH],
            [name: 'NFTContract', classHash: env.NFT_CLASS_HASH],
            [name: 'MarketplaceContract', classHash: env.MARKETPLACE_CLASS_HASH]
        ]

        def verificationSteps = contracts.collectEntries { contract ->
            ["Verify ${contract.name}": {
                sh """
                    voyager verify \
                      --network mainnet \
                      --class-hash ${contract.classHash} \
                      --contract-name ${contract.name} \
                      --watch \
                      --format json > verification-${contract.name}.json
                """

                def result = readJSON file: "verification-${contract.name}.json"
                if (result.has_failed) {
                    error("Verification failed for ${contract.name}")
                }
            }]
        }

        parallel verificationSteps
    }

    stage('Report Results') {
        sh '''
            for file in verification-*.json; do
                CONTRACT=$(echo $file | sed 's/verification-\\(.*\\)\\.json/\\1/')
                STATUS=$(jq -r '.status' $file)
                echo "$CONTRACT: $STATUS"
            done
        '''
    }
}
```

## CircleCI

### Basic Configuration

```yaml
version: 2.1

orbs:
  rust: circleci/rust@1.6.0

jobs:
  build-and-verify:
    docker:
      - image: cimg/rust:latest
    steps:
      - checkout

      - restore_cache:
          keys:
            - cargo-cache-{{ checksum "Cargo.lock" }}
            - cargo-cache-

      - run:
          name: Install Scarb
          command: |
            curl -L https://raw.githubusercontent.com/software-mansion/scarb/main/install.sh | bash
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> $BASH_ENV

      - run:
          name: Install voyager-verifier
          command: cargo install voyager-verifier

      - save_cache:
          key: cargo-cache-{{ checksum "Cargo.lock" }}
          paths:
            - ~/.cargo/bin

      - run:
          name: Build Contract
          command: scarb build --release

      - run:
          name: Deploy Contract
          command: |
            CLASS_HASH=$(./scripts/deploy.sh)
            echo "export CLASS_HASH=$CLASS_HASH" >> $BASH_ENV

      - run:
          name: Verify Contract
          command: |
            voyager verify \
              --network mainnet \
              --class-hash $CLASS_HASH \
              --contract-name MyContract \
              --watch \
              --format json | tee verification-result.json

      - run:
          name: Check Verification
          command: |
            if [ $(jq -r '.has_failed' verification-result.json) = "true" ]; then
              echo "Contract verification failed"
              jq '.' verification-result.json
              exit 1
            fi
            echo "Contract verified successfully"

      - store_artifacts:
          path: verification-result.json

workflows:
  build-deploy-verify:
    jobs:
      - build-and-verify:
          filters:
            branches:
              only:
                - main
                - staging
```

## Environment Variables and Secrets

### GitHub Actions Secrets

```yaml
env:
  CLASS_HASH: ${{ secrets.STARKNET_CLASS_HASH }}
  PRIVATE_KEY: ${{ secrets.STARKNET_PRIVATE_KEY }}
  NETWORK: ${{ vars.NETWORK }}  # Repository variable
```

### GitLab CI Variables

```yaml
variables:
  NETWORK: mainnet  # Project variable
  CLASS_HASH: $CI_CLASS_HASH  # Protected variable
```

### Jenkins Credentials

```groovy
environment {
    CLASS_HASH = credentials('starknet-class-hash')
    PRIVATE_KEY = credentials('starknet-private-key')
}
```

### Best Practices for Secrets

1. **Never commit secrets** to version control
2. **Use CI platform's secret management:**
   - GitHub: Repository Secrets
   - GitLab: CI/CD Variables (protected)
   - Jenkins: Credentials Plugin
   - CircleCI: Context/Project Environment Variables

3. **Rotate secrets regularly**
4. **Use different secrets per environment:**
   ```yaml
   production_class_hash: ${{ secrets.PROD_CLASS_HASH }}
   staging_class_hash: ${{ secrets.STAGING_CLASS_HASH }}
   ```

## Error Handling Patterns

### Retry Logic

```bash
#!/bin/bash
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  voyager verify \
    --network mainnet \
    --class-hash $CLASS_HASH \
    --contract-name MyContract \
    --watch \
    --format json > verification.json

  if [ $(jq -r '.is_completed' verification.json) = "true" ]; then
    if [ $(jq -r '.has_failed' verification.json) = "false" ]; then
      echo "Verification successful"
      exit 0
    else
      echo "Verification failed"
      exit 1
    fi
  fi

  RETRY_COUNT=$((RETRY_COUNT + 1))
  echo "Retry $RETRY_COUNT/$MAX_RETRIES"
  sleep 30
done

echo "Verification timed out after $MAX_RETRIES retries"
exit 1
```

### Timeout Handling

```yaml
- name: Verify with Timeout
  timeout-minutes: 10
  run: |
    voyager verify \
      --network mainnet \
      --class-hash $CLASS_HASH \
      --contract-name MyContract \
      --watch \
      --format json
```

### Failure Notifications

**Slack notification (GitHub Actions):**
```yaml
- name: Notify on Failure
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Contract verification failed for ${{ github.repository }}",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "❌ Contract verification failed\\nBranch: ${{ github.ref }}\\nCommit: ${{ github.sha }}"
            }
          }
        ]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

## Best Practices

### 1. Use Configuration Files

Create environment-specific configs:

```yaml
- name: Select Config
  run: |
    if [ "$ENVIRONMENT" = "production" ]; then
      cp .voyager.prod.toml .voyager.toml
    else
      cp .voyager.dev.toml .voyager.toml
    fi
```

### 2. Cache Installation

```yaml
- name: Cache voyager
  uses: actions/cache@v3
  with:
    path: ~/.cargo/bin/voyager
    key: voyager-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
```

### 3. Use JSON Output

Always use `--format json` in CI for reliable parsing:

```bash
voyager verify --format json > result.json
```

### 4. Enable Watch Mode

Use `--watch` to wait for completion:

```bash
voyager verify --watch --format json
```

### 5. Include Lock Files for Production

```bash
voyager verify --lock-file --network mainnet
```

### 6. Use Verbose Mode for Debugging

```yaml
- name: Verify (Debug)
  if: runner.debug == '1'
  run: |
    voyager verify --verbose --format json
```

### 7. Separate Deployment and Verification

Don't block deployment on verification failure (optional):

```yaml
- name: Verify Contract
  continue-on-error: true  # Don't fail deployment
  run: voyager verify ...
```

## Complete Example: Production-Ready Workflow

```yaml
name: Production Deployment

on:
  push:
    tags:
      - 'v*'

env:
  NETWORK: mainnet
  CARGO_TERM_COLOR: always

jobs:
  deploy-and-verify:
    runs-on: ubuntu-latest
    environment: production

    steps:
      - uses: actions/checkout@v3

      - name: Extract version
        id: version
        run: echo "version=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT

      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/bin
            target/
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Install Scarb
        uses: software-mansion/setup-scarb@v1

      - name: Install voyager-verifier
        run: |
          if ! command -v voyager &> /dev/null; then
            cargo install voyager-verifier
          fi

      - name: Build Contract
        run: scarb build --release

      - name: Deploy to Mainnet
        id: deploy
        env:
          PRIVATE_KEY: ${{ secrets.STARKNET_PRIVATE_KEY }}
        run: |
          CLASS_HASH=$(./scripts/deploy.sh mainnet)
          echo "class_hash=$CLASS_HASH" >> $GITHUB_OUTPUT

      - name: Verify Contract
        timeout-minutes: 10
        run: |
          voyager verify \
            --network mainnet \
            --class-hash ${{ steps.deploy.outputs.class_hash }} \
            --contract-name MyContract \
            --lock-file \
            --watch \
            --format json > verification-result.json

      - name: Validate Verification
        id: validate
        run: |
          IS_COMPLETED=$(jq -r '.is_completed' verification-result.json)
          HAS_FAILED=$(jq -r '.has_failed' verification-result.json)

          if [ "$IS_COMPLETED" != "true" ]; then
            echo "::error::Verification did not complete"
            exit 1
          fi

          if [ "$HAS_FAILED" = "true" ]; then
            echo "::error::Verification failed"
            jq '.' verification-result.json
            exit 1
          fi

          echo "::notice::✅ Contract verified successfully"
          echo "verified=true" >> $GITHUB_OUTPUT

      - name: Create Release
        if: steps.validate.outputs.verified == 'true'
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ steps.version.outputs.version }}
          body: |
            ## Contract Deployment

            - **Network:** Mainnet
            - **Class Hash:** `${{ steps.deploy.outputs.class_hash }}`
            - **Verification:** ✅ Verified
            - **Voyager:** [View on Voyager](https://voyager.online/class/${{ steps.deploy.outputs.class_hash }})

      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: deployment-artifacts
          path: |
            verification-result.json
            target/release/*.sierra.json

      - name: Notify on Failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "❌ Production deployment failed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Deployment Failed*\\nTag: ${{ github.ref }}\\nWorkflow: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

## See Also

- [Output Formats](./output-formats.md) - JSON output parsing for CI/CD
- [Configuration Examples](../configuration/examples.md) - Environment-specific configs
- [Custom Endpoints](./custom-endpoints.md) - Using staging/dev endpoints in CI
- [Lock Files](./lock-files.md) - Reproducible builds for production
- [Batch Verification](../verification/batch-verification.md) - Verifying multiple contracts
