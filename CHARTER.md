# The xCoin Charter

Version 1. Committed in the genesis block of the second chain. This text is the currency. Software, consensus rules, proof of work, signature algorithms and networks are its current implementation and may be replaced; what is written here may not, except where this text itself says how.

## 1. Name and units

The currency is xCoin. Its ticker is XCF. One XCF is one hundred million base units; a base unit is called a sat. Off-chain ledgers may account in one thousandth of a sat, called an msat, and must round to whole sats when they settle on chain.

## 2. Supply

There will never be more than 21,000,000 XCF. Supply is created only by the emission schedule in section 4 and by nothing else. No implementation, successor, ledger, operator or vote may mint. A successor system may re-represent existing units one for one against a proof that the originals are locked.

## 3. Identity and lineage

The identity of the currency is the hash of this text together with the header of the genesis block that commits to it. Every future implementation must be able to prove its lineage back to that genesis. Supply begins at zero in that block. Nothing is carried in from any earlier chain, no earlier chain has any claim on this one, and no balance exists here that was not mined here under section 4.

## 4. Emission

There is no premine, no founder allocation and no carried balance of any kind; supply begins at zero and the founder mines under the same rules as everyone else, from the same first block. From block 1, mining pays exactly 14 XCF per block for 750,000 blocks, seven years and forty-nine days at the target block interval, and the rate then halves every 750,000 blocks, each halving rounded down to a whole satoshi, until it reaches zero: seven cycles of seven carry the chain into its forty-ninth year, and the subsidy fades through the years after, never stopping at once. The scheduled rewards sum to 20,999,999.91 XCF; the last block that pays a subsidy also mints the 0.09 XCF remainder, so the total reaches 21,000,000 XCF to the sat, after which the subsidy is zero. Security of the chain after that point is funded by fees under rules added by the process in section 7, which must be in force before the subsidy ends. The schedule is stated in full in the consensus rules committed with this text and is never changed.

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
