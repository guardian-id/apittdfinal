const ALLOWED_ORIGIN = "https://tandatangansuratpesanan.pages.dev";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin"
    }
  });
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

export async function onRequestPost({ request, env }) {
  if (request.headers.get("Origin") !== ALLOWED_ORIGIN) {
    return json({ success: false, message: "Origin tidak diizinkan." }, 403);
  }

  if (!env.DB) {
    return json({ success: false, message: "Database belum dikonfigurasi." }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, message: "Request JSON tidak valid." }, 400);
  }

  const guid = typeof body.guid === "string" ? body.guid.trim() : "";

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(guid)) {
    return json({ success: false, message: "Link tidak valid." }, 400);
  }

  try {
    const token = await env.DB.prepare(
      SELECT guid, store, doc_number, expires_at, status,
             attempt_count, locked_until
      FROM signing_tokens
      WHERE guid = ?
      LIMIT 1
    ).bind(guid).first();

    if (!token) {
      return json({ success: false, message: "Link tidak valid atau sudah tidak berlaku." }, 404);
    }

    const now = Date.now();

    if (token.status !== "ACTIVE") {
      return json({ success: false, message: "Link sudah digunakan atau tidak aktif." }, 410);
    }

    if (token.locked_until && Date.parse(token.locked_until) > now) {
      return json({ success: false, message: "Link dikunci sementara. Silakan hubungi administrator." }, 429);
    }

    if (!token.expires_at || !Number.isFinite(Date.parse(token.expires_at)) ||
        now >= Date.parse(token.expires_at)) {
      return json({ success: false, message: "Link sudah kedaluwarsa." }, 410);
    }

    return json({
      success: true,
      guid: token.guid,
      store: token.store,
      docNumber: token.doc_number,
      expiresAt: token.expires_at
    });
  } catch (error) {
    return json({ success: false, message: "Terjadi kesalahan saat memvalidasi link." }, 500);
  }
}
