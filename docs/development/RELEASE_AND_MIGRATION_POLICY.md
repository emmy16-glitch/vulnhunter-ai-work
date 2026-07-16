# Release and Migration Policy

## Versioned contracts

Publicly persisted or worker-facing schemas must declare a schema or protocol
version. Incompatible changes require a new version and a documented migration
or compatibility bridge. Silent reinterpretation of stored security records is
forbidden.

## Release checklist

A release candidate requires:

1. changelog update;
2. compatibility-manifest review;
3. Ruff, format, compile, Django, focused, and full test gates;
4. migration review for every persistent schema change;
5. backup and rollback instructions;
6. no tracked secrets, databases, generated evidence, or model artifacts;
7. signed release artifacts when signing infrastructure becomes available.

## Database migrations

Django and other persistent SQL schema changes require committed migration
files, forward and rollback notes, backup verification, and tests against an
existing database. Milestone 31 changes no existing SQL schema, so no migration
file is created.

## Scanner compatibility

Engine or feed upgrades require a reviewed compatibility-manifest change,
checksum/provenance evidence, regression tests, and a new release note. Runtime
code must never resolve an unspecified version to `latest`.
