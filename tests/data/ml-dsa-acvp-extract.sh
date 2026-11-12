#!/usr/bin/env bash
# Regenerates tests/data/ml-dsa-acvp-{sigver,siggen}.json from NIST's public ACVP-Server
# vectors (see tests/data/ml-dsa-acvp-README.md). Requires only curl and jq.
# Usage: tests/data/ml-dsa-acvp-extract.sh
set -euo pipefail

COMMIT=975de31eb83d87039ec88934fdc47d8c312b892d
BASE=https://raw.githubusercontent.com/usnistgov/ACVP-Server/$COMMIT/gen-val/json-files
OUT=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsS -o "$TMP/sigVer.json" "$BASE/ML-DSA-sigVer-FIPS204/internalProjection.json"
curl -fsS -o "$TMP/sigGen.json" "$BASE/ML-DSA-sigGen-FIPS204/internalProjection.json"

# sigVer: per parameter set, in file order, from external/pure/non-externalMu groups:
#   - the first 2 passing cases with a non-empty context,
#   - the first failing case with a non-empty context for each distinct `reason`,
#   - the first case with an empty context (control; ACVP only has failing ones).
jq -c --arg commit "$COMMIT" '
  def keep: {tcId, testPassed, reason, context, message, pk, signature};
  {commit: $commit, mode: "sigVer",
   cases: [
    .testGroups
    | map(select(.signatureInterface == "external" and .preHash == "pure" and .externalMu == false))
    | group_by(.parameterSet)[]
    | {p: .[0].parameterSet, t: [.[].tests[]]}
    | . as $g
    | ($g.t | map(select(.context != "" and .testPassed == true)) | .[0:2]) as $pass
    | ($g.t | map(select(.context != "" and .testPassed == false))
            | group_by(.reason) | map(.[0]) | sort_by(.tcId)) as $fail
    | ($g.t | map(select(.context == "")) | .[0:1]) as $empty
    | ($pass + $fail + $empty)[] | keep + {parameterSet: $g.p}
   ]}' "$TMP/sigVer.json" > "$OUT/ml-dsa-acvp-sigver.json"

# sigGen: per parameter set, in file order, from deterministic external/pure/non-externalMu groups:
#   - the first 2 cases with a non-empty context,
#   - the first case with a 255-byte context (if any),
#   - the first case with an empty context (control).
jq -c --arg commit "$COMMIT" '
  def keep: {tcId, context, message, sk, signature};
  {commit: $commit, mode: "sigGen",
   cases: [
    .testGroups
    | map(select(.signatureInterface == "external" and .preHash == "pure"
                 and .externalMu == false and .deterministic == true))
    | group_by(.parameterSet)[]
    | {p: .[0].parameterSet, t: [.[].tests[]]}
    | . as $g
    | ($g.t | map(select(.context != "")) | .[0:2]) as $some
    | ($g.t | map(select((.context | length) == 510)) | .[0:1]) as $max
    | ($g.t | map(select(.context == "")) | .[0:1]) as $empty
    | ($some + $max + $empty | unique_by(.tcId))[] | keep + {parameterSet: $g.p}
   ]}' "$TMP/sigGen.json" > "$OUT/ml-dsa-acvp-siggen.json"

wc -c "$OUT"/ml-dsa-acvp-sig*.json
