# Help wanted

ai-security-atlas is open to contributions. Below is the hardening work that would make it stronger, roughly in order of impact. Pick anything, comment on (or open) an issue so others know you are on it, and see [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

Found a vulnerability instead? Please report it privately, see [SECURITY.md](SECURITY.md).


### Registry name validation for more ecosystems

**Medium.** PyPI and npm names are now validated before lookup (see the hardening branch). Extend the same idea to any new ecosystems such as Cargo and Go modules.

### Reduce false positives

**Medium.** Run the scanner over popular open source repos, triage the findings and turn each false positive into a regression test.

### More MCP and agent config rules

**Good first issue.** Add detection for risky settings in agent configuration files that are not covered yet, each with a positive and a negative test case.
