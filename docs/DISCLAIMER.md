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
- **External-scanner reports are untrusted input.** `--from-gitleaks`, `--from-trufflehog` and `--from-betterleaks` read a third-party report. An ingested finding is only as accurate as the scanner that produced it, and only `.credactorignore` filters it (an inline `credactor:ignore` does not), so preview with `--dry-run` before redacting.

### Redaction

- **Destructive operation.** `--fix-all` modifies files in place. Backups (`.bak` files) are created by default, and each rewrite goes through a temp file and an atomic rename, so a crash mid-write leaves the original file intact. A disk failure can still lose data, and a process killed mid-run can leave a stray `.credactor.tmp` or `.bak` file next to the file it was writing.
- **Private keys are reported, never rewritten.** `--fix-all` leaves a private key block in place, warns, and counts it as failed. Delete the block by hand and rotate the key.
- **Backup files contain secrets.** A `.bak` file is an unencrypted copy of the original file, credential included. Credactor never adds it to `.gitignore`, so a plain `git add .` would stage it. Add `*.bak` and `*.credactor.tmp` to `.gitignore` and delete the backups once you have checked the result. To keep backups out of the tree, pass `--secure-backup-dir DIR` (a directory outside the repository) on the fix run. `--secure-delete` overwrites and deletes each backup after a successful replacement instead, which leaves version control as your only undo.
- **No undo.** Once a replacement is made, the only recovery is from `.bak` files or version control. There is no built-in rollback.
- **Replacement may break code.** Sentinel values (`REDACTED_BY_CREDACTOR`) will cause runtime failures. This is intentional, since a loud failure is safer than a silent wrong credential, but verify before deploying.
- **A false positive under `--fix-all` rewrites a legitimate value.** Redaction acts on *every* finding, including false positives, so a non-secret that happens to match a pattern (a git commit SHA, an example key, a format-valid placeholder) is replaced with the sentinel, silently corrupting otherwise-correct code or data. This is why `--dry-run` review matters more before `--fix-all` than the detection-only false-positive rate suggests. Always preview and suppress known false positives first.

### False Positives

Credactor reports some false positives. Common sources:

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
- Files covered by `.gitignore` when scanning a directory, which often includes a local `.env`. The text report lists them, but `-f json` and `-f sarif` say nothing about them. To check one, name it directly, for example `credactor --dry-run .env`.
- `.json` files when scanning a directory, unless `--scan-json` is given.
- Commits older than the 100 most recent file-changing commits under `--scan-history`.
- Files that could not be read. By default this is only a warning, so add `--fail-on-error` to a gate that must read every file.
- Base64-encoded or otherwise obfuscated credentials.

## Safe Usage

1. **Always run `--dry-run` first** to review findings before any modification.
2. **Keep backups enabled** (the default). Only use `--no-backup` when files are committed to version control.
3. **Review findings before redacting.** Not every finding is a real credential. Run `credactor .` in a terminal (interactive mode, the default) to answer y/N for each finding, and suppress the ones you keep with `credactor:ignore` or `.credactorignore`.
4. **Rotate leaked credentials.** Redacting a credential from source code does not revoke it. The credential is still valid until rotated at the provider.
5. **Clean git history.** If a credential was committed, removing it from the working tree is not enough. Use `git filter-repo` or BFG Repo Cleaner to rewrite history.
6. **Delete `.bak` files securely** after verifying replacements. They contain the original secrets in plaintext.
7. **Do not rely on Credactor alone.** Its built-in rules cover the credential formats that leak most often, not every provider. Pair it with a dedicated scanner such as Gitleaks, TruffleHog or Betterleaks (Credactor can fix what they find), plus GitHub Secret Scanning and a secrets manager.

## Warranty

This software is provided "as is" under the Apache 2.0 licence, without warranty of any kind. See [LICENSE](../LICENSE) for the full terms.

The authors are not liable for, including without limitation:

- Credentials missed by the scanner
- Code broken by replacements
- Data loss from file modification
- Security incidents resulting from reliance on this tool as a sole control
