# The xCoin Charter

Version 1. Committed in the genesis block of the second chain. This text is the currency. Software, consensus rules, proof of work, signature algorithms and networks are its current implementation and may be replaced; what is written here may not, except where this text itself says how.

## 1. Name and units

The currency is xCoin. Its ticker is XID. One XID is one hundred million base units; a base unit is called a sat. Off-chain ledgers may account in one thousandth of a sat, called an msat, and must round to whole sats when they settle on chain.

## 2. Supply

There will never be more than 100,000,000 XID. Supply is created only by the emission schedule in section 4 and by nothing else. No implementation, successor, ledger, operator or vote may mint. A successor system may re-represent existing units one for one against a proof that the originals are locked.

## 3. Identity and lineage

The identity of the currency is the hash of this text together with the header of the genesis block that commits to it. Every future implementation must be able to prove its lineage back to that genesis. Supply begins at zero in that block. Nothing is carried in from any earlier chain, no earlier chain has any claim on this one, and no balance exists here that was not mined here under section 4.

## 4. Emission

There is no premine, no founder allocation and no carried balance of any kind; supply begins at zero and the founder mines under the same rules as everyone else, from the same first block. Rewards are counted in steps of 110,000 blocks, 382 days at the target interval: step s is blocks 110,000s + 1 to 110,000(s + 1). (a) Blocks 1 to 20,000 pay 6.25 XID, blocks 20,001 to 40,000 pay 12.5 XID, blocks 40,001 to 60,000 pay 25 XID, and blocks 60,001 to 220,000 pay 50 XID. (b) From step 2 (block 220,001) each step has a base reward: the base of the step before, less one tenth of it, that tenth rounded down to a whole hundredth of an XID, and never less than 1.5 XID. The base before step 2 is 50 XID, so step 2 has 45 XID, step 3 has 40.50 XID and step 4 has 36.45 XID. (c) Every block of a step pays its base or one 1,100,000th of the XID not yet scheduled at the start of the step, rounded down to a satoshi, whichever is less. 'Not yet scheduled' means 100,000,000 XID less the rewards this section assigns to all earlier blocks, whatever was actually claimed. So no step pays out more than a tenth of what is left, and once a tenth of what is left is less than 1.5 XID a block, the reward falls by a tenth a step again. (d) From the first step whose blocks would be paid less than 0.1 XID, every block pays 0.1 XID until less than 0.1 XID is left unscheduled. The last of those blocks also mints what is left, so the total is exactly 100,000,000 XID, and the subsidy is zero from the next block. All of this is whole-number arithmetic: writing the base as n hundredths of an XID, the next base is the larger of n - floor(n/10) and 150. The table these words produce, in the row format stated with this section, has SHA-256 356de0dce26aa5e5b9481c3936ecdefb1f81d14dd5e2ca2a43cc7b2775d0a230. Fee rules under section 7 must be in force before block 31,460,001, the first block these rules pay less than 1.5 XID. No fee rule binds sooner than 420,768 blocks (the four-year window of section 7) after it is published, takes more than ten basis points of what a transaction pays out, or takes more than 0.01 XID from any one transaction. The schedule is never changed.

## 5. Ownership

A unit is spendable if and only if the spending condition committed in its output is satisfied. An output commits to a 32-byte root of one or more algorithm-tagged spending conditions. The commitment form is permanent; the set of accepted algorithms is a versioned registry that begins with ML-DSA-65 (FIPS 204) for everyday use and SLH-DSA-SHA2-128s (FIPS 205) as a fallback that shares no assumption with it. SHA-256 is the commitment hash and is the one primitive with no fallback in this version.

## 6. History

Commitments are never truncated. They may be compressed by proofs that a supermajority of node operators accept, and retail activity conducted on ledgers above this chain is not part of its history. Any state a successor publishes must be derivable from this chain.

## 7. Changing the rules

Additions to the rules, including new signature algorithms, new leaf versions, new commitments, new fee rules and additional proof-of-work algorithms mined alongside the first, are made by fork with miner signalling and a published review period. Removals, including the retirement of an algorithm, are made by hard fork with a supermajority of node operators and a migration window of at least four years announced in advance; after the window, outputs under a retired algorithm remain claimable by proof of key knowledge under a successor algorithm. Section 2 and section 4 carry a veto: no process may change them.

## 8. What this chain is for

This chain records supply and ownership, anchors the commitments of ledgers that carry everyday payments, settles between them, and lets anyone leave a failed ledger. It is not a payment rail and its capacity is sized for security and finality, not for retail volume. There is no freeze, no seizure and no administrative key at this layer, and there never will be.

## 9. Custody of this text

The founder signs the first version. Later versions may only add sections 10 and beyond; sections 1 through 9 are fixed. A version is in force when its hash is committed in a block under the process in section 7.
