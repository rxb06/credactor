# Disclaimer

## What Credactor Is

Credactor is a static analysis tool that uses regex patterns and entropy heuristics to find hardcoded credentials in source files. It is a **developer aid**, not a security guarantee.

## What Credactor Is NOT

- Not a replacement for secret management (use Vault, AWS Secrets Manager, 1Password, etc.)
- Not a runtime security tool: it scans files at rest, not live applications
- Not a compliance certification tool
- Not guaranteed to catch every credential format or encoding
- Not a verifier: it does not check whether a detected value is a live, active credential (a finding may be expired, rotated, revoked, or a non-secret look-alike)

## Limitations

### Detection

- **Regex-based.** Credactor matches known patterns (AWS keys, GitHub tokens, JWTs, etc.) and heuristics (entropy, variable names). Novel or obfuscated credential formats will be missed.
- **Recognised file types only.** Credactor scans a fixed set of source/config extensions (`.py`, `.js`, `.env`, `.yaml`, `.toml`, `.txt`, …), **not every file**. Binaries, images, archives, encrypted blobs, and text files of unrecognised types (e.g. `.md`, custom extensions) are skipped **during directory scans** unless added via `extra_extensions` in `.credactor.toml` (a file named explicitly as the scan target is always scanned, whatever its extension). General-purpose scanners that read every file will catch secrets in types Credactor skips.
- **No cross-file tracking.** A credential split across two files (e.g. key in one, secret in another) is not detected.
- **Entropy thresholds are tunable, not perfect.** Lowering them catches more but increases false positives. The defaults balance precision and recall for common codebases.
- **No semantic analysis.** The tool does not understand code execution flow. A credential constructed at runtime from multiple variables will not be detected.
- **External-scanner ingestion is BETA.** `--from-gitleaks` / `--from-trufflehog` ingest a third-party report as **untrusted input**; ingested findings are best-effort and should be reviewed especially carefully before redaction.

### Redaction

- **Destructive operation.** `--fix-all` modifies files in place. Whilst backups are created by default (`.bak` files), a crash or disc failure during replacement could still cause data loss.
- **Backup files contain secrets.** `.bak` files are unencrypted copies of the original file with the credential intact. Delete them securely after verifying replacements.
- **No undo.** Once a replacement is made, the only recovery is from `.bak` files or version control. There is no built-in rollback.
- **Replacement may break code.** Sentinel values (`REDACTED_BY_CREDACTOR`) will cause runtime failures. This is intentional, since a loud failure is safer than a silent wrong credential, but verify before deploying.
- **A false positive under `--fix-all` rewrites a legitimate value.** Redaction acts on *every* finding, including false positives, so a non-secret that happens to match a pattern (a git commit SHA, an example key, a format-valid placeholder) is replaced with the sentinel, silently corrupting otherwise-correct code or data. This is why `--dry-run` review matters more before `--fix-all` than the detection-only false-positive rate suggests. Always preview and suppress known false positives first.

### False Positives

Credactor is actively improving false positive rates, but they are not yet zero. Common sources:

- High-entropy strings that are not credentials (UUIDs, encoded data, internal IDs, git commit SHAs)
- Variable names matching credential patterns with non-secret values
- Format-valid placeholders and example keys (e.g. the canonical AWS `AKIA…EXAMPLE` documentation value), which deterministic provider patterns flag regardless of entropy
- IDE-generated files and build artefacts with hash-like content

Always run `--dry-run` first and review findings before redacting. Use `.credactorignore`, inline `# credactor:ignore` comments, or `.credactor.toml` to suppress known false positives.

### False Negatives

**A run with no findings is not proof the code is secret-free.** It means only that nothing matched Credactor's patterns and heuristics, not that no secrets exist. Do not treat a clean scan as a security sign-off. Secrets are missed in cases such as:

- Credentials in formats not covered by built-in patterns.
- Credentials below the entropy threshold.
- Values shorter than the minimum length (default 8 characters).
- Credentials in binary, CSV, PDF, or other non-scanned file types.
- Base64-encoded or otherwise obfuscated credentials.

## Safe Usage

1. **Always run `--dry-run` first** to review findings before any modification.
2. **Keep backups enabled** (the default). Only use `--no-backup` when files are committed to version control.
3. **Review findings before redacting.** Not every finding is a real credential. Use interactive mode (the default) to decide per-finding.
4. **Rotate leaked credentials.** Redacting a credential from source code does not revoke it. The credential is still valid until rotated at the provider.
5. **Clean git history.** If a credential was committed, removing it from the working tree is not enough. Use `git filter-repo` or BFG Repo Cleaner to rewrite history.
6. **Delete `.bak` files securely** after verifying replacements. They contain the original secrets in plaintext.
7. **Do not rely on Credactor alone.** Use it alongside GitHub Secret Scanning, pre-commit hooks, and a secrets manager for defence in depth.

## Warranty

This software is provided "as is" under the Apache 2.0 licence, without warranty of any kind. See [LICENSE](../LICENSE) for the full terms.

The authors are not liable for, including without limitation:

- Credentials missed by the scanner
- Code broken by replacements
- Data loss from file modification
- Security incidents resulting from reliance on this tool as a sole control
