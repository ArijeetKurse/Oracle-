export function createSingleFlight(): {
  readonly active: boolean;
  run<T>(operation: () => Promise<T>): Promise<T | undefined>;
};
export function retryAfterMilliseconds(value: string | null, now?: number): number;
