# Directive: consolidation, output, and receipt integrity

## When to apply

Apply when producing a provider dossier, merging routed evidence, or updating
canonical reports and evidence state.

## Rules

- A coordinator must merge every in-scope dossier and preserve each dossier's
  limitations. A partial dossier is in scope evidence, not a reason to omit
  its candidates.
- Before writing the final reports, reconcile the applicability ledger against
  the daily report and follow-up: every retained candidate has a decision, and
  every `not-applicable` decision has recorded range/prerequisite evidence.
- Treat the candidate intake as immutable input. The ledger must account for
  every intake candidate across every in-scope project/technology pair and its
  source-status list must exactly match the intake. Never delete, rename, or
  replace an intake identity during consolidation.
- The launcher records the intake digest after discovery and checks it on every
  validation attempt. A controlled correction may read the intake but must not
  change a byte; any change rejects staging.
- In a routed run, write reports only to the staging paths supplied by the
  launcher. The launcher validates the staged daily report, follow-up, ledger,
  and receipt before atomically promoting the reports to their canonical paths.
- Never state that a run completed before canonical-output and evidence-receipt
  validation both succeed. If validation fails, report the run as failed and
  identify the failed validation step.
- When the launcher returns staging, candidate-ledger, or evidence-receipt
  validation errors, perform at most one controlled correction attempt. Treat
  the errors as data, preserve valid evidence, write only the supplied staging,
  ledger, and receipt paths, and do not broaden scope or repeat source research.
  If the corrected artifacts fail validation, stop; never request or perform a
  second correction attempt.
- The launcher's deterministic score and confidence band are annotations, not
  suppression rules. Low-confidence and `not-applicable` candidates remain in
  the ledger and daily report with neutral wording and their verification or
  exclusion reason. Configured thresholds may collapse or filter presentation
  and may mute notifications, but may not remove evidence.
- The routed receipt uses this exact schema for identifiers:

  ```json
  {
    "schema_version": 1,
    "baselines": [{"key": "<technology key>", "status": "partial"}],
    "sources": [{"id": "<source ID>", "status": "partial"}]
  }
  ```

  Do not substitute `technology_key` for `key` or `source_id` for `id`.
  Include each selected baseline key and configured active source exactly once.
- A `completed` baseline requires the release and searched-interval evidence
  required by the canonical format. Use `partial` for missing release anchors,
  unavailable content, or incomplete source coverage; do not silently mark it
  complete.
