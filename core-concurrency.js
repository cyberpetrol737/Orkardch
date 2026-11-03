'use strict';

/** Run fn over items with at most `limit` in flight. Results keep input order; errors become {error}. */
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try { results[i] = await fn(items[i], i); } catch (error) { results[i] = { error }; }
    }
  };
  const n = Math.max(1, Math.min(limit || 1, items.length || 1));
  await Promise.all(Array.from({ length: n }, worker));
  return results;
}

module.exports = { mapLimit };
