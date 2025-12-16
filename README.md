# eIDAS Trust Anchors
The purpose of this utility is to parse the EU list of trust lists and glean
the set of qualified website authentication certificate (QWAC) trust anchors, as well as the trust anchors used for signing and sealing.
Additionally, it can compare the set it comes up with against the set currently
in Chrome.

## Example Usage
`$ cargo run -- -d tls -o download -o process -o compare --extension QWACS`

To extract qualified signature anchors instead, specify the relevant extension (e.g. `--extension QCForESig` or `--extension ForeSignatures`).

This will download the set of anchors in Chrome, the list of trust lists, and
each list identified by that list (recursively). Downloaded artifacts are saved
in the directory `tls`. Once downloaded, the lists are parsed and the set of
QWAC trust anchors are saved in `tls/trust_anchors.pem`. Finally, Chrome's list
is compared against the parsed set, with any differences printed out.
