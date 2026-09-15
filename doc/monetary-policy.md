> # ⛔ SUPERSEDED — HISTORICAL DOCUMENT
>
> **This is not xCoin's monetary policy and never was.** It was written for the
> earlier NEX design: a two-token architecture in which NEX was a reserve asset,
> wrapped as **UMX** on **CORE** — a separate, external chain — with **KnexPay** as
> the payment interface and a bridge reserve backing issuance.
>
> **None of that exists.** xCoin has no wrapped token, no bridge, no reserve policy
> and no relationship to CORE. `UMX`, `KnexPay` and `Lumero` appear nowhere in the
> source. No code has ever implemented anything described below.
>
> xCoin's actual monetary policy is `contrib/regenesis/CHARTER.md`, whose SHA-256 is
> committed in the genesis coinbase: 21,000,000 XCF, no premine, 14 XCF per block
> from block 1, halved every 750,000 blocks until it reaches zero (~2248); seven
> eras of seven years carry it into its 49th year. The consensus implementation is
> `GetBlockSubsidy` in `src/validation.cpp`
> and the emission table in `src/consensus/params.h`.
>
> Kept for provenance. Do not cite it for anything.

# Monetary Policy — Wrapped NEX on Lumero/CORE

**Version:** Draft 1.1  
**Status:** Working proposal  
**Scope:** NEX base chain, wrapped NEX as UMX on CORE, KnexPay wallet behavior, bridge reserve policy

---

## 1. Purpose

This document defines the monetary relationship between:

- **NEX** — the reserve settlement asset on the NEX base chain
- **UMX** — wrapped NEX on CORE, used as the fast transaction unit
- **KnexPay** — the wallet and payment interface that manages movement between them

The central objective is:

> **NEX holds value. UMX moves value.**

The system is designed so that:
- NEX is the primary reserve and settlement asset
- UMX is the wrapped, spend-layer representation of locked NEX on CORE
- value can move between reserve and velocity states cleanly
- system behavior favors **gravitational return to NEX**

This is not intended to be two competing currencies. It is intended to be **one monetary system with two functional states**.

---

## 2. Core Monetary Principle

### 2.1 NEX as Gravity
NEX is the asset where value is meant to rest.

NEX should be used for:
- reserve balances
- treasury balances
- long-term user savings
- final settlement
- bridge collateral
- monetary reporting

NEX is the anchor asset.

### 2.2 UMX as Velocity
UMX is wrapped NEX on CORE. It is the unit where value is meant to move.

UMX should be used for:
- instant payments
- tap-to-pay
- merchant acceptance
- working balances
- app-native microtransactions
- short-duration transactional liquidity

UMX is the movement layer.

### 2.3 Monetary Hierarchy
The system should always maintain this hierarchy:

1. **NEX is the superior reserve unit**
2. **UMX is wrapped NEX and subordinate to NEX**
3. **All issued UMX must be explainable in terms of locked NEX backing**
4. **Treasury and long-term balances should resolve back to NEX**

---

## 3. Unit Structure

### 3.1 Ledger Precision
Internal ledger/accounting precision must use **8 decimal places**.

All storage and bridge accounting must be handled in integer base units.

### 3.2 Human Display Precision
For ordinary user-facing interfaces:
- default display precision for UMX should be **up to 3 decimals**
- full 8-decimal precision remains available for audits, technical screens, exports, and reconciliation

### 3.3 Conversion Ratio
The initial recommended policy is a fixed conversion ratio:

- **1 NEX = 1000 UMX**

This ratio is recommended because it gives:
- human-friendly transaction sizing
- intuitive everyday prices
- clean psychological denomination for retail use

Under this model:
- 1 UMX = 0.001 NEX
- if NEX uses 8 decimal places internally, then 1 UMX corresponds to 100,000 raw NEX units

This ratio should be fixed and published clearly.

---

## 4. Asset Model

### 4.1 NEX
NEX is:
- the reserve asset
- the settlement asset
- the bridge collateral asset
- the treasury asset
- the primary unit of net worth

### 4.2 UMX
UMX is:
- wrapped NEX on CORE
- the payment unit on CORE
- the velocity unit of the monetary system
- the user-facing spend denomination
- the fast-layer representation of locked NEX value

### 4.3 UMX Is Not an Independent Monetary Competitor
UMX should not be framed as a rival reserve asset.

UMX must be presented as:
- wrapped NEX
- a transactional representation of locked NEX
- a fast movement unit
- a spend-layer instrument
- a subordinate monetary state relative to NEX

---

## 5. Reserve Invariant

The bridge must maintain a public monetary invariant.

### 5.1 Core Reserve Rule

> **Locked NEX on the reserve side must equal issued UMX value on the transaction side, according to the published conversion ratio.**

If:
- 1 NEX = 1000 UMX

Then:
- every 1 NEX locked in reserve authorizes issuance of 1000 UMX on CORE
- every 1000 UMX redeemed destroys that amount and releases 1 NEX back to reserve ownership

### 5.2 Published Reserve Data
The system should publish:
- NEX reserve/lock addresses
- total bridged/locked NEX
- total issued UMX
- bridge mint events
- bridge burn/redeem events
- reserve proofs or equivalent auditable state reports

### 5.3 Non-Negotiable Backing Rule
UMX may only be created through one of these paths:
- lock of NEX into bridge reserve
- explicit genesis/testnet issuance marked as non-production

UMX must not be issued as an unrelated floating asset if the goal is to preserve NEX gravity.

---

## 6. Bridge Policy

### 6.1 NEX → UMX (Convert Into Velocity)
This direction should be:
- fast
- low friction
- low fee or subsidized
- easy to access through the wallet

Process:
1. User chooses to move value from reserve into spend
2. NEX is locked on the NEX chain
3. The bridge verifies required confirmations
4. Equivalent UMX is issued on CORE
5. Wallet spend balance increases

### 6.2 UMX → NEX (Return to Gravity)
This direction should remain available at all times, but may be more disciplined.

Process:
1. User chooses to move value from spend into reserve
2. UMX is burned or locked on CORE
3. The bridge verifies finality and redemption eligibility
4. Equivalent NEX is released from reserve
5. Wallet reserve balance increases

### 6.3 Directional Bias
The system should intentionally favor:
- using UMX for spending
- ending in NEX for reserve

This bias should come from:
- wallet defaults
- merchant settlement rules
- reserve reporting
- treasury behavior
- optional sweep policies

This bias should not come from arbitrary confiscation or user-hostile behavior.

---

## 7. Wallet Policy (KnexPay)

KnexPay should present the monetary system as two coordinated balances:

- **Reserve Balance (NEX)**
- **Spend Balance (UMX)**

### 7.1 User Experience Principle
The wallet should make this feel intuitive:

- hold in NEX
- spend in UMX
- sweep back to NEX

### 7.2 Automatic Spend Float
Users should be able to define a UMX operating float.

Recommended controls:
- **minimum spend threshold**
- **target spend balance**
- **maximum spend float**

#### Example
- minimum spend threshold: 50 UMX
- target spend balance: 150 UMX
- maximum spend float: 300 UMX

Behavior:
- if spend balance falls below 50 UMX, top up from reserve to 150 UMX
- if spend balance rises above 300 UMX, sweep excess back to reserve

This makes UMX behave like working balance rather than savings.

### 7.3 Default Wallet Bias
The default wallet behavior should treat NEX as primary.

Examples:
- portfolio summary emphasizes NEX reserve
- default “net worth” view uses NEX
- UMX is presented as available spending balance
- sweep-to-reserve is enabled by default for new users unless they opt out

---

## 8. Merchant Policy

Merchants are one of the strongest places to enforce monetary gravity.

### 8.1 Merchant Acceptance
Merchants should be able to:
- accept UMX instantly
- hold a configurable UMX working float
- settle excess value into NEX automatically

### 8.2 Merchant Float Model
Example:
- merchant keeps 2,000 UMX operating float
- any excess over that float is automatically swept to NEX
- sweep occurs hourly, every 6 hours, or daily depending on preference

### 8.3 Merchant Treasury Principle
Merchants should be encouraged to think:
- UMX = point-of-sale liquidity
- NEX = treasury reserve

This aligns economic activity with NEX accumulation.

---

## 9. Treasury Policy

Treasury should overwhelmingly prefer NEX.

### 9.1 Treasury Rules
Treasury balances should be reported primarily in NEX.

UMX treasury balances should be minimized and used only for:
- operational liquidity
- payouts in transit
- payment rail buffering
- short-term working needs

### 9.2 Treasury Statement Rule
All official financial statements should treat NEX as the reserve denominator.

UMX should appear as:
- transaction inventory
- operational float
- short-duration liquidity

not as the ultimate reserve benchmark.

---

## 10. Incentive Policy

### 10.1 Reward NEX, Not UMX Parking
If the system later introduces rewards or incentives, those rewards should favor:
- holding NEX
- returning value to reserve
- maintaining reserve discipline
- participating in verifiable bridge liquidity support

The system should avoid rewarding indefinite passive parking in UMX.

### 10.2 Utility of UMX
UMX should win on:
- convenience
- speed
- spendability
- merchant acceptance
- instant transfer

It should not win on:
- long-term reserve preference
- primary balance prestige
- treasury dominance

---

## 11. Pricing and Reporting Policy

### 11.1 User Prices
Retail and everyday prices may be shown in UMX.

This is recommended because UMX is more human-sized and easier for daily mental arithmetic.

### 11.2 Reserve Statements
Long-term wealth, reserve summaries, treasury reports, and settlement reports should be expressed in NEX.

### 11.3 Dual Display
Where appropriate, the wallet should offer:
- primary display in UMX for daily use
- secondary equivalent in NEX
or
- primary display in NEX for reserve screens
- secondary equivalent in UMX

This dual-display policy reinforces the hierarchy without confusing users.

---

## 12. Monetary Guardrails

The system must avoid the following failure states:

### 12.1 UMX Becomes the True Store of Value
This is a policy failure.

If users, merchants, and treasury all prefer to sit indefinitely in UMX, then NEX loses monetary gravity.

Countermeasures:
- reserve-first wallet design
- auto-sweep policies
- NEX-denominated reporting
- NEX-favoring treasury rules

### 12.2 Ambiguous Backing
If users do not understand whether UMX is backed, native, bridged, or synthetic, the system becomes unstable and loses trust.

Countermeasure:
- publish exact asset model
- publish reserve invariant
- publish bridge and supply data

### 12.3 Competing Narratives
The system should not tell users:
- “NEX is the real money”
- while also implying
- “UMX is the better money”

UMX should be described as:
- faster
- easier
- more practical for spending
- wrapped NEX for the fast layer

NEX should be described as:
- stronger
- deeper
- more final
- the reserve layer

---

## 13. Recommended Public Framing

The strongest concise description is:

> **NEX is the reserve asset. UMX is wrapped NEX in motion on Lumero/CORE.**

Alternative phrasing:
- Hold in NEX. Spend in UMX.
- NEX is gravity. UMX is motion.
- NEX stores value. UMX circulates value.
- NEX settles. UMX flows.
- UMX is NEX on the fast layer.

Avoid calling UMX a “stablecoin” unless it is actually stabilized against an external peg.

The more accurate framing is:
- wrapped NEX
- payment denomination
- transaction unit
- velocity unit
- spend-layer representation of NEX value

---

## 14. Rollout Policy

### Phase 1
- launch NEX as reserve chain
- launch UMX on CORE as wrapped NEX transaction unit
- manual convert-in / convert-out
- visible dual balances in wallet

### Phase 2
- add auto-top-up from NEX to UMX
- add auto-sweep from UMX to NEX
- add merchant reserve settlement policies

### Phase 3
- add treasury dashboards
- add reserve proofs
- add public invariant reporting
- optimize wallet defaults around reserve discipline

---

## 15. Final Monetary Rule

The system should always resolve toward this behavior:

> **Value rests in NEX, moves through wrapped NEX as UMX, and returns to NEX.**

That is the policy.

If implemented correctly:
- NEX wins as gravity
- UMX wins as velocity
- users get fast payments
- merchants get working liquidity
- reserve discipline remains intact

---

## 16. Summary

### NEX
- reserve
- settlement
- treasury
- savings
- gravity

### UMX
- wrapped NEX
- spend
- payments
- merchant liquidity
- app speed
- velocity

### KnexPay
- unified wallet
- reserve/spend orchestration
- auto-top-up
- auto-sweep
- dual-balance UX

### Monetary Goal
Create a system where:
- NEX is the primary asset
- UMX is the wrapped fast payment state of NEX
- movement is easy
- reserve is favored
- the public story stays simple and strong
