/** Sliding-window limiter. NVD without a key allows 5 requests per 30 seconds. */
export class RateLimiter {
  private stamps: number[] = [];

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number,
  ) {}

  tryAcquire(): boolean {
    const time = this.now();
    this.stamps = this.stamps.filter((stamp) => time - stamp < this.windowMs);
    if (this.stamps.length >= this.limit) return false;
    this.stamps.push(time);
    return true;
  }
}

export function nvdLimit(hasApiKey: boolean): { limit: number; windowMs: number } {
  return hasApiKey ? { limit: 50, windowMs: 30_000 } : { limit: 5, windowMs: 30_000 };
}
