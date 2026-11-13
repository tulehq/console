# htmx

The console serves htmx from its own binary; nothing is loaded from a CDN.

| | |
|---|---|
| Version | 2.0.11 |
| File | `internal/web/static/htmx.min.js`, the package's `dist/htmx.min.js`, unmodified |
| Source | npm package `htmx.org`, `https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.11.tgz` |
| Tarball integrity (npm) | `sha512-Thx/WtpeOQqSrqBCw/A1cwGJGg4UrVa3+sW0GmrM3p4gJgO89ecH4qtbnyzDDWFvBTqjnIMCgELTNt636dtamA==` |
| SHA-256 of `htmx.min.js` | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| License | Zero-Clause BSD, in [LICENSE](LICENSE) |

`TestVendoredHTMX` in `internal/web/web_test.go` fails unless the served
file has the SHA-256 above.

To move to another release, download the package's tarball, check it
against the `integrity` the registry lists for that version, copy its
`dist/htmx.min.js` over the served file, and update the version and both
checksums here, and the SHA-256 in `internal/web/web_test.go`.
