export function createSingleFlight() {
  let active = false;
  return {
    get active() { return active; },
    async run(operation) {
      if (active) return undefined;
      active = true;
      try { return await operation(); }
      finally { active = false; }
    },
  };
}

export function retryAfterMilliseconds(value, now = Date.now()) {
  if (!value) return 0;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1000);
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - now) : 0;
}
