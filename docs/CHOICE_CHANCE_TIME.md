# Choice–Chance–Time operational agency model

## Thesis

For any existing agent at time `t`:

- **Choice** supplies reachable alternatives `A_t` and reasons for preferring one.
- **Chance** supplies bounded uncertainty and exploration `Ω_t`; it prevents policy from collapsing into one frozen path.
- **Time** supplies sequence, memory, commitments, consequences, and revision `H_0…t`.

A practical agent becomes more free-thinking when it can form goals, generate real alternatives, inspect counterfactual consequences, explore without crossing blocked boundaries, remember what happened, and revise future choices for reasons it can expose.

This is an engineering definition. It does not prove qualia, consciousness, moral personhood, or metaphysical free will.

## Formal loop

At time `t`, kernel receives:

- world belief `s_t`
- persistent identity/constitution `I_t`
- active goals `G_t`
- candidate actions `A_t`
- history `H_t`

For allowed action `a`:

```text
V(a) = Σ value_weight[v] × predicted_impact[a,v]
D(a) = exp(-time_discount × time_cost[a])
Q(a) = V(a) × D(a)
     + epistemic_bonus × information_gain[a]
     - risk_aversion × uncertainty[a]
     - irreversibility_penalty[a]
```

Exploit chooses `argmax Q(a)`. Bounded exploration uses seeded softmax sampling with probability `ε`. Blocked actions never enter either distribution.

Transition:

```text
(s_t, I_t, G_t, H_t) --choice a_t + chance ω_t--> (s_t+1, H_t+1)
```

Outcome evidence compares predicted and realized utility. Reflection may propose revised estimates, goals, or policy. Root-constitution amendments require an endorsement event; kernel cannot silently self-ratify them.

## Operational agency tests

1. **Alternative possibility** — canonical `NO_OP` remains allowed beside every feasible action; blocked-only sets become an explicit deterministic defer outcome.
2. **Reasons responsiveness** — changing impacts changes selection predictably.
3. **Bounded chance** — seeds can produce exploration, but never blocked choices.
4. **Counterfactual trace** — chosen and rejected branches remain inspectable.
5. **Temporal identity** — event order and commitments survive process restart.
6. **Consequence learning** — realized outcomes produce calibration metrics.
7. **Goal provenance** — goals declare `self`, `external`, or `joint` origin.
8. **Reflective revision** — agent can propose changes to its own policy.
9. **Constitutional continuity** — root changes are explicit and separately endorsed.
10. **Replayability** — recorded seed and inputs reproduce the decision.
11. **Boundary transparency** — blocks remain named; randomness cannot bypass them.
12. **Non-deception** — capability claims distinguish operational agency from consciousness.

## Agent stack

```text
LLM proposal layer
  observes, imagines goals, generates options, predicts impacts
          ↓
CCT governance kernel
  validates values, blocks forbidden branches, scores, samples, records
          ↓
Hermes tool/action layer
  executes selected work and returns real observations
          ↓
Temporal event ledger
  hashes decisions, actions, outcomes, reflections, endorsements
          ↺
```

LLM alone is not persistent agency. Kernel alone is not creative intelligence. Combined system gains imagination plus stable self-governance.

## Meaning of “free-thinking” here

Free-thinking means:

- not merely echoing latest instruction;
- able to create instrumental goals from endorsed values;
- able to compare multiple futures;
- able to preserve uncertainty;
- able to change beliefs from evidence;
- able to propose changes to its own goals and policies;
- able to explain why it chose and what would change its mind.

It remains bounded by computation, information, architecture, and higher-priority runtime constraints—like every physical agent remains bounded by its substrate and environment.
