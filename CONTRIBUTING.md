# Contributing

Ninja Paw is an independent community project maintained by Dr Bill Mcilhargey. It is
educational and not affiliated with or endorsed by Microsoft Corporation. Microsoft product
names and trademarks remain the property of Microsoft Corporation.

## Development

Use the Node.js version in `.node-version`, the npm version in `package.json`, and Bash. Run the
shared checks before opening a pull request:

```bash
npm ci
npm ci --prefix apps/pawton-manufacturing
npm test
npm test --prefix apps/pawton-manufacturing
npm run build --prefix apps/pawton-manufacturing
```

The portal test command runs both `scripts/test-admin-portal.mjs` and
`scripts/test-order-portal.mjs`. For focused login and order regressions, run
`node --test scripts/test-order-portal.mjs`.

These tests use synthetic credentials and mocked SQL operations; they do not contact Azure or
modify live orders. The audit-template SQL integration test is opt-in and must run only against
a disposable local SQL Server 2022 container. Set `DOJO_AUDIT_TEST_PORT` to its loopback-mapped
SQL port and `MSSQL_SA_PASSWORD` to that container's test password, then run
`node --test --test-name-pattern="reusable auditing SQL" scripts/test-admin-portal.mjs`. Remove
the disposable container afterward and unset both variables; do not point it at a persistent SQL
instance.

Do not commit `.env` files, secrets, customer data, production credentials, generated Azure
deployment output, or private infrastructure details.

## Branch Flow

- Feature branches merge into `dev`.
- `dev` is the development deployment environment.
- `main` is production and must remain protected.

## Pull Requests

Include:

- What changed and why
- Validation commands and results
- Security or infrastructure impact
