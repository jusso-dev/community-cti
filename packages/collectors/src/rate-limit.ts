export class RateLimiter {
  private stamps: number[] = [];

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number,
  ) {}

  /** Returns how long the caller should wait. Zero means the call is allowed now. */
  delayForNext(): number {
    const now = this.now();
    this.stamps = this.stamps.filter((stamp) => now - stamp < this.windowMs);
    if (this.stamps.length < this.limit) {
      this.stamps.push(now);
      return 0;
    }
    return this.windowMs - (now - this.stamps[0]!);
  }
}

export function nvdLimit(hasKey: boolean): { limit: number; windowMs: number } {
  return hasKey ? { limit: 50, windowMs: 30_000 } : { limit: 5, windowMs: 30_000 };
}
