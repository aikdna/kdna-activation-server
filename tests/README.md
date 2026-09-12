# Current tests

`npm test` selects `current-observer.test.mjs` and the current public-surface gate. They use only synthetic records and private temporary directories; HTTP tests bind 127.0.0.1 on OS-assigned ports and close their own connections. Other tests and legacy files are retained historical coverage for 0.2.1 and are not assertions about this release candidate.
