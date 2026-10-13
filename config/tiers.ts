/**
 * Hypothetical fair-use ceilings, not prices and not validated unit economics.
 * The README prices are separate hypotheses. See issue 46.
 */
export const TIERS = {
  community: { monthlyAud: 15, hypothesis: true },
  community_plus: { monthlyAud: 40, hypothesis: true },
  business: { monthlyAud: 120, hypothesis: true },
  managed: { monthlyAud: 400, hypothesis: true },
} as const;

export type TierName = keyof typeof TIERS;
