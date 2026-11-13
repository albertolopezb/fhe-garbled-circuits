# Security-level check (rule 6 of the brief)

Checked on 2026-11-12 against the Homomorphic Encryption Standard, November 2018,
"Tables of Recommended Parameters", Table 1 (cost model BKZ.sieve, classical),
distribution (-1, 1) (uniform ternary secret), error width sigma ~ 3.2.
Source read directly (PDF pages 24-25):
https://homomorphicencryption.github.io/assets/HomomorphicEncryptionStandard2018.pdf

Rows read for the 128-bit security level:

| n     | max log q | uSVP  | dec   | dual  |
|-------|-----------|-------|-------|-------|
| 1024  | 27        | 131.6 | 160.2 | 138.7 |
| 2048  | 54        | 129.7 | 144.4 | 134.2 |
| 4096  | 109       | 128.1 | 134.9 | 129.9 |
| 8192  | 218       | 128.5 | 131.5 | 129.2 |
| 16384 | 438       | 128.1 | 129.9 | 129.0 |
| 32768 | 881       | 128.5 | 129.1 | 128.5 |

## What this supports

- The application's parameters (N = 2^14, log QP = 438, Lattigo default secret
  `ring.Ternary{P: 2/3}`, default error sigma = 3.2) sit exactly on the 128-bit
  row of this table (estimated cost 128.1 bits for uSVP).
- The harness compares log2(QP) of every E4 parameter set with this table
  (`bench.HEStd2018Ternary128`, column `he_std2018_status` in `results/e4_sets.csv`).

## What this does NOT establish

- The table is from 2018 (lwe-estimator commit 560525). It was not re-run with
  the current lattice estimator, and the newer "Security Guidelines for
  Implementing Homomorphic Encryption" tables were not consulted. A current
  estimate may be lower than 128 bits.
- Table 2 of the same document (cost model BKZ.ADPS16) is stricter; it was not
  used here.
- The table covers single-key RLWE. The collective key is the sum of two
  ternary secrets and E2S adds flooding noise; no separate estimate was made
  for the multiparty setting.
- Sparse secrets (`ternary_h192` in E4) are explicitly not covered by the
  standard ("significantly better known attacks"); those sets are marked
  `not_covered`, not secure.
- This is a parameter-table lookup. It says nothing about the garbled circuit,
  the oblivious transfer, or the semi-honest protocol composition.
