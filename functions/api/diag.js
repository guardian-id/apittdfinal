
export async function onRequestGet({ env }) {
  return new Response(
    JSON.stringify({
      hasDB: Boolean(env.DB),
      dbType: typeof env.DB,
      hasPrepare: typeof env.DB?.prepare === "function"
    }),
    {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    }
  );
}
