export async function boundedBody(
  request: Request,
  limit: number,
): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("missing");
  const chunks: Uint8Array[] = [];
  let size = 0,
    timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), 4000);
  });
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      size += value.length;
      if (size > limit) throw new Error("size");
      chunks.push(value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks),
    );
  } catch (e) {
    void reader.cancel().catch(() => {});
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
