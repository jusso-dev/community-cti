/** Production data plane. Australian regions only. No other default. */
export const DEFAULT_DATA_REGION = "ap-southeast-2";
export const DEFAULT_EMAIL_REGION = "ap-southeast-2";

export const AU_REGIONS = new Set([
  "ap-southeast-2",
  "ap-southeast-4",
  "australiaeast",
  "australiasoutheast",
]);

export function assertAustralianRegion(region: string): void {
  if (!AU_REGIONS.has(region)) {
    throw new Error(
      `Region ${region} is outside Australia. Add an approved entry to the residency exceptions register before use. Cultural data is never an exception.`,
    );
  }
}
