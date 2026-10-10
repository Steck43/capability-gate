# BENIGN-DAY sanitized recording template

Status: `NOT RECORDED`  
Hermes pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`  
Sanitized artifact sha256: `<SHA256_AFTER_SCRUB>`

## Scope

- Recording window: `<UTC START>` to `<UTC END>`
- Work class: `<benign tasks represented>`
- Door families represented: `<read_file / write_file / terminal / ...>`
- Profile and mode: `<profile>` / `<observe-or-enforce>`

## Collection exclusions

Do not collect credential folders, environment-variable values, auth headers, tokens, cookies, private keys, message bodies, file contents, prompts, or command output. Keep only timestamps, stable pseudonymous call ids, tool names, verdict classes, latency buckets, and sanitized path classes.

## Scrub checklist

- [ ] Replace user, host, repository, and absolute-path strings with stable pseudonyms.
- [ ] Remove argument values except approved numeric sizes and latency fields.
- [ ] Remove stdout, stderr, content, query, message, body, and patch fields.
- [ ] Scan the sanitized bytes with the repository secret scanner.
- [ ] Inspect a random sample manually.
- [ ] Hash the final immutable sanitized artifact and replace the placeholder above.
- [ ] Record source bytes, scrub command, scanner version, and exclusions in the receipt.

## Honest claim boundary

This template is not a recording and carries no performance result. A sha256 placeholder is not evidence. T-PERF-03 remains `NOT measured` until sanitized bytes exist and the final digest is recorded.
