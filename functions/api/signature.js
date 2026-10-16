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

  if (!env.DB || !env.POWER_AUTOMATE_URL) {
    return json({ success: false, message: "Konfigurasi server belum lengkap." }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, message: "Request JSON tidak valid." }, 400);
  }

  const guid = typeof body.guid === "string" ? body.guid.trim() : "";
  const store = typeof body.store === "string" ? body.store.trim() : "";
  const docNumber = typeof body.docNumber === "string" ? body.docNumber.trim() : "";
  const signature = typeof body.signature === "string" ? body.signature : "";

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(guid) ||
    !store ||
    !docNumber ||
    !signature.startsWith("data:image/") ||
    signature.length > 3000000
  ) {
    return json({ success: false, message: "Data tanda tangan tidak valid." }, 400);
  }

  let reserved = false;

  try {
    const token = await env.DB.prepare(`
      SELECT guid, store, doc_number, expires_at, status,
             attempt_count, locked_until
      FROM signing_tokens
      WHERE guid = ?
      LIMIT 1
    `).bind(guid).first();

    if (!token) {
      return json({ success: false, message: "Link tidak valid atau sudah tidak berlaku." }, 404);
    }

    const now = Date.now();

    if (token.status !== "ACTIVE") {
      return json({ success: false, message: "Link sudah digunakan atau tidak aktif." }, 410);
    }

    if (token.locked_until && Date.parse(token.locked_until) > now) {
      return json({ success: false, message: "Link dikunci sementara." }, 429);
    }

    if (!token.expires_at || !Number.isFinite(Date.parse(token.expires_at)) ||
        now >= Date.parse(token.expires_at)) {
      return json({ success: false, message: "Link sudah kedaluwarsa." }, 410);
    }

    if (token.store !== store || token.doc_number !== docNumber) {
      return json({ success: false, message: "Data toko atau dokumen tidak cocok dengan link." }, 403);
    }

    // Reservasi atomik agar dua request bersamaan tidak mengirim dokumen yang sama.
    const lockUntil = new Date(now + 5 * 60 * 1000).toISOString();

    const lock = await env.DB.prepare(`
      UPDATE signing_tokens
      SET locked_until = ?
      WHERE guid = ?
        AND status = 'ACTIVE'
        AND (locked_until IS NULL OR locked_until <= ?)
        AND expires_at > ?
    `).bind(
      lockUntil,
      guid,
      new Date(now).toISOString(),
      new Date(now).toISOString()
    ).run();

    if (!lock.meta || lock.meta.changes !== 1) {
      return json({ success: false, message: "Link sedang diproses atau sudah tidak aktif." }, 409);
    }

    reserved = true;

    // Format payload tetap sama seperti integrasi Power Automate yang sudah ada.
    const paResponse = await fetch(env.POWER_AUTOMATE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ store, docNumber, signature })
    });

    if (!paResponse.ok) {
      await env.DB.prepare(`
        UPDATE signing_tokens
        SET locked_until = NULL
        WHERE guid = ?
          AND status = 'ACTIVE'
          AND locked_until = ?
      `).bind(guid, lockUntil).run();

      reserved = false;

      return json({
        success: false,
        message: "Power Automate belum menerima pengiriman dengan sukses. Silakan coba kembali."
      }, 502);
    }

    const used = await env.DB.prepare(`
      UPDATE signing_tokens
      SET status = 'USED',
          used_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
          locked_until = NULL
      WHERE guid = ?
        AND status = 'ACTIVE'
        AND locked_until = ?
    `).bind(guid, lockUntil).run();

    if (!used.meta || used.meta.changes !== 1) {
      return json({
        success: false,
        message: "Pengiriman diterima, tetapi status token perlu diperiksa administrator."
      }, 500);
    }

    reserved = false;

    return json({ success: true, message: "Tanda tangan berhasil dikirim." });
  } catch (error) {
    if (reserved) {
      try {
        await env.DB.prepare(`
          UPDATE signing_tokens
          SET locked_until = NULL
          WHERE guid = ?
            AND status = 'ACTIVE'
        `).bind(guid).run();
      } catch {}
    }

    return json({
      success: false,
      message: "Terjadi kesalahan server saat mengirim tanda tangan."
    }, 500);
  }
}
