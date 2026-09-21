# Documentation Publication Policy

## Public Material

Publish reproducible installation/configuration instructions, API and SDK contracts,
security assumptions, supported behavior, known limitations, migration requirements,
license notices and release verification procedures. A control is not certified
merely because it is implemented or associated with a standard.

Keep material limitations visible in `LIMITATIONS.md` and the relevant technical
guide. Release approval requires artifact-specific vulnerability scans, signed
inventories, provenance and deployment evidence. Internal report removal must not
be used to describe an unapproved candidate as production-ready or vulnerability-free.

## Local-Only Material

Internal plans, staffing/commercial estimates, agent debates, exploratory reviews,
lab execution ledgers, host paths, recovery histories and environment-specific
resource identifiers are not public product documentation. The explicit
publication-boundary block in `.gitignore` lists existing local-only records.
They remain in place for continuity; new notes belong under ignored `docs/internal/`.
Generated evidence, backups and credentials remain under ignored storage, never
in a release documentation bundle.

Do not create public links to those records. Publish independently reviewed,
sanitized summaries only when useful, with precise scope and no unsupported claims.
General technical procedures belong in public guides; executed run logs do not.
Existing public roadmaps and security advisories are not automatically private.

## Verification Before Publication

Run `python -m pytest tests/test_documentation_publication.py -q` and inspect the
staged diff before any commit. The tests reject tracked local-only paths and public
Markdown references to classified private records, including on a fresh checkout
where private files are absent. They are not a general secret scanner.

Git ignores prevent normal accidental addition, not `git add -f`, history leaks,
filesystem copies or external uploads. CI checks provide a second boundary but do
not replace human review. Never archive or upload the entire working directory.
`git archive` includes tracked content only, but still requires review of the tracked
file set. Docker separately excludes `docs/`, `shared/`, `reports/` and `debates/`;
required runtime licenses/notices remain explicitly included.

Do not rewrite published history or delete recovery evidence as routine cleanup.
If sensitive data has already been published, follow the incident process and
rotate affected credentials; adding an ignore rule does not remove past exposure.
