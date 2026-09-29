import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Polling hook (the recommended beginner-friendly real-time option).
 * Re-runs `fetcher` every `intervalMs` while `enabled`, pauses while the tab
 * is hidden, and exposes a manual refresh().
 */
export function usePolling(fetcher, deps, { intervalMs = 5000, enabled = true } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const refresh = useCallback(async () => {
    try {
      const result = await fetcherRef.current();
      setData(result);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    refresh();
    if (!enabled) return undefined;
    const id = setInterval(() => {
      if (document.visibilityState === "visible") refresh();
    }, intervalMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled, intervalMs]);

  return { data, error, loading, refresh, lastUpdated };
}
