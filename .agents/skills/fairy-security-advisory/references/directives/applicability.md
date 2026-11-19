# Directive: deterministic applicability and complete candidate accounting

## When to apply

Apply to every technology/version candidate selected by an advisory source,
including historical baselines and partial source runs.

## Required matching process

1. Read the immutable candidate intake and build one applicability-ledger row
   for every candidate/project/technology combination it requires. Preserve
   `candidate_id`, source ID, and the exact advisory identifier. Record the
   project, technology key, declared value, affected range, prerequisite
   status, and decision.
2. Preserve the intake affected-range fields. The launcher, not the AI,
   computes `range_relation` deterministically from the authoritative declared
   value and `affected_constraints`; it overwrites any proposed relation before
   scoring. A known fixed version may be excluded only with that range evidence.
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
7. Do not invent a correspondence percentage. The launcher computes the score
   deterministically from advisory identity, source quality, version relation,
   prerequisites, and extraction completeness. Thresholds change display and
   notification behavior only; they never change candidate accounting or the
   applicability decision.

## Historical and selected-technology checks

- A selected baseline with an unresolved release date is partial, not empty.
  Consult the configured sources within the available boundary and retain
  relevant candidates with explicit historical-coverage limits.
- A source candidate relevant to a selected technology must appear in the
  ledger even when the source pass is partial. Partial coverage prevents a
  completion claim and checkpoint advance; it does not erase candidates that
  were found.
- Every exact bulletin, source-record, CVE, and GHSA identifier carried by the
  intake must survive into the staged daily report and, for actionable items,
  the staged follow-up. A generic replacement does not satisfy this rule.
- For an actionable ledger row, the exact identifiers and its project must
  occur in the same follow-up table row. Global mentions elsewhere in the file
  do not establish a finding-to-project association.
- When the same advisory applies to multiple projects with equivalent work,
  consolidate it into one follow-up row and list every project in its `Project`
  cell. Keep rows separate only when evidence, owner, status, action, or
  completion criteria differ.
