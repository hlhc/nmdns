<!--
Thanks for contributing to nmdns!
Please fill out the sections below. Delete what is not applicable.
-->

## Summary

<!-- One or two sentences describing what this PR does and why. -->

## Related issues

<!-- e.g. Closes #123, Refs #456 -->

## Type of change

- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (config / CLI / on-wire behaviour)
- [ ] Documentation only
- [ ] Build / CI / packaging
- [ ] Refactor / internal cleanup

## RFC 6762 / 6763 impact

<!--
If this changes on-wire behaviour, name the section(s) of RFC 6762 or 6763 it
touches and how the change preserves conformance. Otherwise write "None".
-->

## Testing

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --all-features`
- [ ] `nix flake check` (if Nix files were touched)
- [ ] Manual testing: <!-- describe -->

## Checklist

- [ ] I have read [`README.md`](../README.md) and the project license.
- [ ] My changes generate no new warnings.
- [ ] I have added or updated tests covering my changes.
- [ ] I have updated the man page (`man/nmdns.1`) if user-visible behaviour changed.
- [ ] I have updated the example config (`examples/nmdns.toml`) if config keys changed.
