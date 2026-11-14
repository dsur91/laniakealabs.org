# Laniakea Labs

Source of [laniakealabs.org](https://laniakealabs.org): the research page of an independent lab, a data snapshot, and the public proof tree of a sealed forward record.

The lab asks one question and tests it forward: can a model learn to read the raw trade tape of a market, when it is examined only on time beyond its training? Bitcoin is the test domain because its data is public and its answers arrive within hours.

## What is sealed

Every 20 seconds the model either makes a call (up or down) or stays silent. Every one of those steps is committed before its outcome exists.

- Each step is a salted commitment: `SHA256(domain || 32-byte salt || canonical public claim)`. The claim holds only the direction and its times.
- Every five minutes the commitments close into a Merkle root signed with Ed25519, with an RFC 3161 timestamp and an inclusion proof in the Sigstore transparency log.
- Every hour the root is anchored in the Bitcoin blockchain through OpenTimestamps.
- A call is revealed with its salt after the market has answered. Each UTC day opens in full, silences included, 96 hours after it ends.
- Nothing is backdated. A gap is declared in a signed document and stays visible.

Sealing began on 30 August 2026. The official record starts on 3 September 2026, 00:00 UTC.

## Check it yourself

```
git clone https://github.com/dsur91/laniakealabs.org
cd laniakealabs.org
python3 proof/tools/verify_public_track_v5.py --public-root proof --witness-chain
```

The verifier is written in Python with the standard library only, and it calls three command-line tools: `openssl`, `cosign` and `ots`. It checks every seal one by one, so allow it time. It needs nothing from us.

It checks the cryptographic integrity of the chain and reports three separately labelled figures: signal hit, coverage and contract score. Exit code 0 means an official, final PASS; 1 means HOLD; 2 means provisional.

To re-judge every revealed call yourself, download the exchange's public BTCUSDT trade files and add `--binance-tape <folder>`.

For a first look without a terminal, the "Check a seal" card on the main page recomputes a revealed call's fingerprint, Merkle path and signatures in your browser.

## What is in `proof/`

| Path | Contents |
|---|---|
| `GENESIS.json`, `PUBLIC_KEY.pem`, `SPEC.json` | the genesis, the signing key and the public specification |
| `witnesses/` | one signed five-minute witness per window, with its Sigstore bundle |
| `hours/` | hourly roots with their OpenTimestamps receipts |
| `reveals/` | every revealed call: claim, salt and Merkle path to its witness |
| `judgements/` | every revealed call judged against the exchange's public tape |
| `packs/`, `manifests/` | complete UTC days and their timestamped manifests |
| `amendments/`, `specs/`, `methodology/` | signed amendments, judge specifications and their history |
| `trust/` | trust roots used by the verifier |
| `tools/` | the verifiers and their tests; v5 is current |

The tree in this repository is a snapshot, refreshed weekly. Its date is shown on [laniakealabs.org/proof](https://laniakealabs.org/proof/).

## What this proves, and what it does not

It proves when each call was made and that none was added, altered or quietly dropped afterwards.

It does not prove which model made a call, and it says nothing about the future. The live record is still short: we will not draw a verdict on it before May 2027. The method has been tested in one domain so far; its generality is a hypothesis, not a result.

Nothing here is investment advice.

## Using it for your own predictions

The specification (`proof/SPEC.json`) and the verifier are public. Any lab or evaluation team can seal its own predictions the same way, so that no model is credited for an answer it has already seen.

## Who made this

One person, Dmitriy Surkov, and the frontier models he works with. The questions, the custody of the data and every release are his. The code was written by models, mostly Claude, and the commits say so.
