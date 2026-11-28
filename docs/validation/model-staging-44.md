# Approved endpoint model staging, FED04 #44

Local validation on Linux with Go 1.27.4 and PostgreSQL 18.7. The controller
test uses the real enrollment, model registry and promotion repositories with
a synthetic tunnel peer. The endpoint test uses real HTTP transfers and the
private identity store with a test-only publisher key and evaluation fixtures.

| Check | Evidence |
| --- | --- |
| Registry approval and authorization | `TestMeshApprovedModelDownloadPostgres` returns 404 for an unapproved candidate, then returns the signed metadata and exact bytes after FED10 promotion. An unknown or revoked peer gets 403. The route is absent from the regular controller API. |
| Registry change during download | When a second promotion changes the active digest, requesting the first digest returns 404. A malformed digest returns 400. |
| Endpoint verification | `TestDownloadAndStageApprovedModel` refuses metadata for another deployment, missing approval digest, an oversized claim, invalid signature, and incompatible runtime or feature order before requesting bytes. It refuses tampered or malformed signed payloads before staging. |
| Interruption and retry | The test truncates the HTTP body with the original Content-Length. A first interruption publishes no file. A successful retry discards a simulated uncommitted temp file. Later rejected downloads preserve both the verified stage and the active inference result. |

`make check`, `make cross-build`, `make contract-check`,
`make database-check` and `make browser-check` passed. The Python model suite
ran 104 tests as part of `make check`. The database run included the existing
endpoint enrollment and mesh evidence tests. The browser run exercised the
existing console suite using Chrome 158.

The transfer tests use a local HTTP fixture, while the database test supplies
the tunnel peer at the mesh HTTP boundary. This does not qualify a model
transfer over a deployed relay or a Windows LocalService staging run. The
repository's Linux service tests and Windows build cover regression and
compilation respectively. Endpoint activation, native Windows power loss and
chain operations are outside this validation.
