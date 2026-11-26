// Fixed-destination readiness probe. The review tree ships with no upstream binding.
type ProbeResult = {
  status: string;
  checkedAt: string;
  reason:
    | "ready"
    | "timeout"
    | "network"
    | "invalid_response"
    | "upstream_unavailable";
};
const TARGET = "https://readiness.example.invalid/readyz";
export function statusService(fetcher: typeof fetch = fetch, clock = Date.now) {
  let cached: ProbeResult | undefined;
  let expires = 0;
  let pending: Promise<ProbeResult> | undefined;
  return async function check() {
    if (cached && clock() < expires) return cached;
    if (pending) return pending;
    pending = (async () => {
      let status = "unavailable";
      let reason: ProbeResult["reason"] = "network";
      try {
        const response = await fetcher(TARGET, {
          method: "GET",
          redirect: "error",
          cache: "no-store",
          signal: AbortSignal.timeout(10000),
        });
        reason =
          response.status === 200 ? "invalid_response" : "upstream_unavailable";
        const reader = response.body?.getReader();
        if (!reader) throw Error();
        const chunks: Uint8Array[] = [];
        let total = 0;
        try {
          for (;;) {
            const part = await reader.read();
            if (part.done) break;
            total += part.value.byteLength;
            if (total > 128) throw Error();
            chunks.push(part.value);
          }
        } finally {
          await reader.cancel();
        }
        const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (
          response.status === 200 &&
          value.status === "ok" &&
          Object.keys(value).length === 1
        ) {
          status = "ready";
          reason = "ready";
        }
      } catch (error) {
        if (
          error instanceof Error &&
          ["TimeoutError", "AbortError"].includes(error.name)
        )
          reason = "timeout";
      }
      cached = { status, reason, checkedAt: new Date(clock()).toISOString() };
      expires = clock() + 30000;
      return cached;
    })();
    try {
      return await pending;
    } finally {
      pending = undefined;
    }
  };
}
// Review exports have no service to probe. An operator must review and bind a
// fixed upstream before enabling this integration.
export const checkReadiness = statusService(async () => {
  throw new Error("Readiness upstream is unconfigured");
});
