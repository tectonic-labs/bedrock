# ML-DSA ACVP known-answer subset

Test vectors for FIPS 204 ML-DSA with a context string, used by `tests/ml_dsa_acvp.rs`.

## Source

- Repository: <https://github.com/usnistgov/ACVP-Server> (National Institute of Standards and
  Technology), pinned to commit `975de31eb83d87039ec88934fdc47d8c312b892d`.
- Files (under `gen-val/json-files/`):
  - `ML-DSA-sigVer-FIPS204/internalProjection.json` (vsId 42)
  - `ML-DSA-sigGen-FIPS204/internalProjection.json`
- Extracted subsets (this directory): `ml-dsa-acvp-sigver.json`, `ml-dsa-acvp-siggen.json`.
  These are **modified** (reduced) copies of the NIST data: only the cases chosen below are kept,
  and only the fields the tests need. Values are otherwise unaltered. Subset created
  2026-11-12 by `ml-dsa-acvp-extract.sh`.

## NIST notice (reproduced from the repository README, "License")

> NIST-developed software is provided by NIST as a public service. You may use, copy, and
> distribute copies of the software in any medium, provided that you keep intact this entire
> notice. You may improve, modify, and create derivative works of the software or any portion of
> the software, and you may copy and distribute such modifications or works. Modified works should
> carry a notice stating that you changed the software and should note the date and nature of any
> such change. Please explicitly acknowledge the National Institute of Standards and Technology
> as the source of the software.
>
> NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND,
> EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE
> IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA
> ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE
> UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE
> ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT
> LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
>
> You are solely responsible for determining the appropriateness of using and distributing the
> software and you assume all risks associated with its use, including but not limited to the
> risks and costs of program errors, compliance with applicable laws, damage to or loss of data,
> programs or equipment, and the unavailability or interruption of operation. This software is not
> intended to be used in any situation where a failure could cause risk of injury or damage to
> property. The software developed by NIST employees is not subject to copyright protection within
> the United States.

## Subset selection (deterministic; see `ml-dsa-acvp-extract.sh`)

Only groups with `signatureInterface: external`, `preHash: pure`, `externalMu: false`. Per
parameter set (ML-DSA-44, -65, -87), in file order:

- sigVer: the first 2 passing cases with a non-empty context; the first failing non-empty-context
  case for each distinct `reason` (modified message / signature commitment / z / hint); and the
  first empty-context case. ACVP's only empty-context sigVer cases are failing ones, so there is
  no passing empty-context control here (the sigGen empty-context case covers that path).
- sigGen: only groups with `deterministic: true` (expected signature is reproducible; the hedged
  groups publish no `rnd`). The first 2 non-empty-context cases, the first 255-byte-context case,
  and the first empty-context case.

## Key formats

ACVP `pk` is the FIPS 204 encoded public key and `sk` is the FIPS 204 encoded (expanded) secret
key (e.g. 2560 bytes for ML-DSA-44), the same encodings Bedrock's `from_raw_bytes` takes. No
conversion is needed. The sigVer files carry no usable `sk`, so it is dropped.

Regenerate with `tests/data/ml-dsa-acvp-extract.sh` (needs only `curl` and `jq`).
