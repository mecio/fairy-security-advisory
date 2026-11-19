# Directive: deterministic applicability and complete candidate accounting

## When to apply

Apply to every technology/version candidate selected by an advisory source,
including historical baselines and partial source runs.

## Required matching process

1. Build an applicability ledger for every relevant source candidate and every
   selected project technology entry. Record the project, technology key,
   declared value, advisory identifier, affected range, prerequisite status,
   and decision.
2. Match exact versions deterministically against the affected and fixed
   ranges. A known fixed version may be excluded only with that range evidence.
3. Treat a declared range, minimum, caret, tilde, wildcard, or other
   non-exact populated value as a range. If it overlaps an advisory's affected
   range, retain the candidate. Do not discard it because the actual installed
   version is unknown.
4. If range semantics cannot be resolved safely, retain a low-confidence
   follow-up or monitor item and state the needed verification. Do not convert
   the uncertainty into an exclusion.
5. Evaluate prerequisites after version matching. A prerequisite confirmed as
   absent can support `not-applicable`; an unknown prerequisite must remain a
   limitation attached to the retained candidate.
6. Account for every ledger row exactly once as `immediate-action`,
   `follow-up`, `monitor`, or `not-applicable`. State the evidence for an
   exclusion in the report.

## Historical and selected-technology checks

- A selected baseline with an unresolved release date is partial, not empty.
  Consult the configured sources within the available boundary and retain
  relevant candidates with explicit historical-coverage limits.
- A source candidate relevant to a selected technology must appear in the
  ledger even when the source pass is partial. Partial coverage prevents a
  completion claim and checkpoint advance; it does not erase candidates that
  were found.
- When the same advisory applies to multiple projects with equivalent work,
  consolidate it into one follow-up row and list every project in its `Project`
  cell. Keep rows separate only when evidence, owner, status, action, or
  completion criteria differ.
