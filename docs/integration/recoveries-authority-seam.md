# Recoveries ↔ Anar-Core authority seam

Recoveries owns the economic conclusion, evidence sufficiency, pricing, attribution, payment allocation, and fee calculation. Anar-Core owns only the current technical-authority decision over the normalized capability request.

For an external recovery notice, Recoveries supplies:

- internal organization ID;
- authority context ID;
- registered capability ID and version;
- exact opportunity/evidence object digest;
- requested resource and effect scope;
- bounded constraints;
- product-policy evidence references, including adjudication approval where required;
- exact payload hash.

Anar-Core may return `ALLOW`, `REQUIRE_APPROVAL`, or a fail-closed denial with reason codes and a receipt. A valid product assertion can satisfy a policy requirement but cannot create membership, delegation, entitlement, or administrative authority.

The action runner must verify at effect time:

- receipt and envelope integrity;
- exact organization, capability, resource, effect, purpose, payload hash, and constraints;
- current authority through a fresh decision for consequential or deferred effects;
- no downstream widening.

Until that integration is deployed and independently proven, Recoveries must retain its local deterministic denial behavior and must not describe local fixtures as live Anar-Core authority.

