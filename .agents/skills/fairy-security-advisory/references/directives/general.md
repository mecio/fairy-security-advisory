# Directive: advisory reasoning invariants

## When to apply

Apply to every advisory check, evidence dossier, consolidation, and report
update.

## Rules

- Keep source facts, inventory values, installed values, and production facts
  distinct. Missing evidence in one category never overwrites a populated value
  in another.
- Treat every populated inventory, manual, and production version or version
  constraint as an applicability boundary. This includes exact versions,
  version ranges, minimums, and manually supplied values.
- Inventory quality and GUI status are evidence labels only. They may change
  the confidence and wording of a conclusion, but they must never suppress,
  narrow, replace, or exclude a populated value during advisory matching.
- Do not use a newer version found in another project, container, lockfile, or
  local runtime to replace a distinct declared value.
- An unverified prerequisite or deployment context yields a qualified finding
  or human-review outcome. It is not evidence that an advisory is irrelevant.
- A `not-applicable` conclusion requires positive, recorded evidence that the
  declared applicability boundary cannot intersect the affected range or that
  a required prerequisite is absent. “Not checked”, “unknown”, “partial”, and
  “not installed locally” are not `not-applicable` evidence.
- Before delivering results, challenge every omission: identify the version
  boundary and source evidence that justify it. Retain only conclusions that
  pass this check; record unresolved items as limitations or follow-up.
