/**
 * Hypothetical fair-use limits copied from the README pricing hypotheses.
 * Not a price list and not a decision. Justin Middler has not accepted a price.
 */
export const TIERS_ARE_HYPOTHESES = true;

export interface TierHypothesis {
  id: "community" | "community_plus" | "business" | "managed";
  label: string;
  hypotheticalPriceAud: number;
  monthlyAgentAud: number;
  monthlyEnrichmentAud: number;
}

export const TIERS: readonly TierHypothesis[] = [
  { id: "community", label: "Community", hypotheticalPriceAud: 0, monthlyAgentAud: 5, monthlyEnrichmentAud: 2 },
  { id: "community_plus", label: "Community Plus", hypotheticalPriceAud: 29, monthlyAgentAud: 20, monthlyEnrichmentAud: 10 },
  { id: "business", label: "Business", hypotheticalPriceAud: 99, monthlyAgentAud: 80, monthlyEnrichmentAud: 40 },
  { id: "managed", label: "Managed Intelligence", hypotheticalPriceAud: 299, monthlyAgentAud: 200, monthlyEnrichmentAud: 100 },
];

export function tierById(id: string): TierHypothesis | undefined {
  return TIERS.find((tier) => tier.id === id);
}
