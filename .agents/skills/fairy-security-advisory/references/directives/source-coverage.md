# Directive: source coverage and advisory extraction

## When to apply

Apply while collecting or interpreting ACN, vendor, project, CVE, registry, or
other configured source evidence.

## Rules

- Start with ACN. For each selected, technology-relevant ACN bulletin, record
  its URL, title, identifiers, affected and fixed versions, prerequisites,
  publication date, and extraction outcome before drawing an applicability
  conclusion.
- A reachable index page, bounded API page, truncated response, blocked page,
  or unparsed bulletin is partial coverage. Record the limitation and do not
  advance the source checkpoint.
- Do not infer that a bulletin is irrelevant from its title, from a missing
  keyword in a bounded response, or from an unverified platform assumption.
  Open the bulletin and confirm it with the primary vendor/project or CVE
  record whenever available.
- If a source reveals an advisory relevant to a selected technology, add it to
  the applicability ledger immediately. Later source failures may lower
  coverage confidence but may not remove that candidate.
- If source access is unavailable, distinguish “not retrieved” from
  “not applicable”. Report the former as a coverage limitation and preserve
  any candidate evidence already collected.
