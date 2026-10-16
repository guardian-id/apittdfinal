const ALLOWED_ORIGIN = "https://tandatangansuratpesanan.pages.dev";

const GUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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

// Parse waktu dari database secara konsisten.
// Nilai tanpa zona waktu (mis. "2026-10-16 16:59:59") dianggap UTC,
// sama seperti perilaku SQLite. Disarankan menyimpan dengan akhiran Z
// atau offset (mis. "2026-10-16T23:59:59+07:00").
function parseDbTime(value) {
  if (typeof value !== "string" || !value.trim()) return NaN;

  let text = value.trim();

  if (/^\d{4}-\d{2}-\d{2} /.test(text)) {
    text = text.replace(" ", "T");
  }

  if (/^\d{4}-\d{2}-\d{2}T[\d:.]+$/.test(text)) {
    text += "Z";
  }

  return Date.parse(text);
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

  const guid = body && typeof body.guid === "string" ? body.guid.trim() : "";

  if (!GUID_REGEX.test(guid)) {
    return json({ success: false, message: "Link tidak valid." }, 400);
  }

  try {
    const token = await env.DB.prepare(`
      SELECT guid, store, doc_number, expires_at, status, locked_until
      FROM signing_tokens
      WHERE guid = ?
      LIMIT 1
    `).bind(guid).first();

    if (!token) {
      return json({ success: false, message: "Link tidak valid atau sudah tidak berlaku." }, 404);
    }

    const now = Date.now();

    // Pengiriman sedang diproses, atau hasilnya belum dapat dipastikan.
    // Dibedakan dari USED agar user tidak mengira link bisa dipakai lagi.
    if (token.status === "SENDING") {
      return json({
        success: false,
        message: "Pengiriman tanda tangan sedang diproses atau menunggu pengecekan administrator."
      }, 409);
    }

    if (token.status !== "ACTIVE") {
      return json({ success: false, message: "Link sudah digunakan atau tidak aktif." }, 410);
    }

    if (token.locked_until && parseDbTime(token.locked_until) > now) {
      return json({
        success: false,
        message: "Link sedang dikunci sementara. Silakan coba lagi nanti atau hubungi administrator."
      }, 429);
    }

    const expiresAtMs = parseDbTime(token.expires_at);

    if (!Number.isFinite(expiresAtMs) || now >= expiresAtMs) {
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
    console.error("validate: kesalahan saat memvalidasi link:", error);

    return json({ success: false, message: "Terjadi kesalahan saat memvalidasi link." }, 500);
  }
}
