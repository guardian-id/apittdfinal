const ALLOWED_ORIGIN = "https://tandatangansuratpesanan.pages.dev";

const GUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Frontend mengirim canvas.toDataURL("image/png"), jadi hanya PNG yang diterima.
// Prefix "iVBORw0KGgo" adalah signature (magic bytes) file PNG dalam base64.
const PNG_DATA_URL_PREFIX = "data:image/png;base64,iVBORw0KGgo";
const PNG_DATA_URL_REGEX = /^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/;

const MAX_SIGNATURE_LENGTH = 3000000;
const MAX_BODY_LENGTH = MAX_SIGNATURE_LENGTH + 10000;

// Durasi reservasi. Harus lebih panjang dari PA_TIMEOUT_MS.
const LOCK_MS = 5 * 60 * 1000;
const PA_TIMEOUT_MS = 20000;

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
// Nilai tanpa zona waktu dianggap UTC, sama seperti perilaku SQLite
// (julianday) yang dipakai pada query di bawah.
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

// Power Automate menolak secara pasti (request tidak diproses):
// semua 4xx kecuali 408 (timeout, hasil tidak pasti).
// 5xx, 408, timeout, dan error jaringan dianggap TIDAK PASTI.
function isDefiniteRejection(status) {
  return status >= 400 && status < 500 && status !== 408;
}

async function releaseToActive(env, guid, lockUntil) {
  return env.DB.prepare(`
    UPDATE signing_tokens
    SET status = 'ACTIVE',
        locked_until = NULL
    WHERE guid = ?
      AND status = 'SENDING'
      AND locked_until = ?
  `).bind(guid, lockUntil).run();
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

  // Batasi ukuran body sebelum diparse.
  const declaredLength = Number(request.headers.get("Content-Length"));

  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_LENGTH) {
    return json({ success: false, message: "Ukuran data terlalu besar." }, 413);
  }

  let rawBody;
  try {
    rawBody = await request.text();
  } catch {
    return json({ success: false, message: "Request tidak dapat dibaca." }, 400);
  }

  if (rawBody.length > MAX_BODY_LENGTH) {
    return json({ success: false, message: "Ukuran data terlalu besar." }, 413);
  }

  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ success: false, message: "Request JSON tidak valid." }, 400);
  }

  if (!body || typeof body !== "object") {
    return json({ success: false, message: "Request JSON tidak valid." }, 400);
  }

  const guid = typeof body.guid === "string" ? body.guid.trim() : "";
  const store = typeof body.store === "string" ? body.store.trim() : "";
  const docNumber = typeof body.docNumber === "string" ? body.docNumber.trim() : "";
  const signature = typeof body.signature === "string" ? body.signature : "";

  if (
    !GUID_REGEX.test(guid) ||
    !store ||
    !docNumber ||
    signature.length > MAX_SIGNATURE_LENGTH ||
    !signature.startsWith(PNG_DATA_URL_PREFIX) ||
    !PNG_DATA_URL_REGEX.test(signature)
  ) {
    return json({ success: false, message: "Data tanda tangan tidak valid." }, 400);
  }

  let reserved = false;
  let sendStarted = false;
  let lockUntil = null;

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

    // Request lain sedang mengirim, atau pengiriman sebelumnya tidak pasti.
    // Dalam kedua kasus, JANGAN kirim ulang.
    if (token.status === "SENDING") {
      const sendingUntil = parseDbTime(token.locked_until);

      if (Number.isFinite(sendingUntil) && sendingUntil > now) {
        return json({ success: false, message: "Link sedang diproses." }, 409);
      }

      return json({
        success: false,
        uncertain: true,
        message: "Status pengiriman sebelumnya belum dapat dipastikan. Silakan hubungi administrator."
      }, 409);
    }

    if (token.status !== "ACTIVE") {
      return json({ success: false, message: "Link sudah digunakan atau tidak aktif." }, 410);
    }

    if (token.locked_until && parseDbTime(token.locked_until) > now) {
      return json({ success: false, message: "Link dikunci sementara." }, 429);
    }

    const expiresAtMs = parseDbTime(token.expires_at);

    if (!Number.isFinite(expiresAtMs) || now >= expiresAtMs) {
      return json({ success: false, message: "Link sudah kedaluwarsa." }, 410);
    }

    if (token.store !== store || token.doc_number !== docNumber) {
      return json({ success: false, message: "Data toko atau dokumen tidak cocok dengan link." }, 403);
    }

    // Reservasi atomik: ACTIVE -> SENDING.
    // Hanya satu request yang bisa lolos, sehingga dua request bersamaan
    // tidak mengirim dokumen yang sama. Perbandingan waktu memakai julianday()
    // agar tidak bergantung pada format string tanggal.
    const nowIso = new Date(now).toISOString();
    lockUntil = new Date(now + LOCK_MS).toISOString();

    const lock = await env.DB.prepare(`
      UPDATE signing_tokens
      SET status = 'SENDING',
          locked_until = ?
      WHERE guid = ?
        AND status = 'ACTIVE'
        AND (locked_until IS NULL OR julianday(locked_until) <= julianday(?))
        AND julianday(expires_at) > julianday(?)
    `).bind(lockUntil, guid, nowIso, nowIso).run();

    if (!lock.meta || lock.meta.changes !== 1) {
      return json({ success: false, message: "Link sedang diproses atau sudah tidak aktif." }, 409);
    }

    reserved = true;

    // Format payload tetap sama seperti integrasi Power Automate yang sudah ada.
    // guid dikirim sebagai header idempotency key (bukan bagian body) supaya
    // flow Power Automate dapat mendeteksi pengiriman ganda bila diperlukan.
    let paResponse;
    sendStarted = true;

    try {
      paResponse = await fetch(env.POWER_AUTOMATE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Idempotency-Key": guid
        },
        body: JSON.stringify({ store, docNumber, signature }),
        signal: AbortSignal.timeout(PA_TIMEOUT_MS)
      });
    } catch (error) {
      // Timeout atau jaringan putus: Power Automate mungkin sudah menerima.
      // Status dibiarkan SENDING agar link tidak bisa dikirim ulang.
      console.error("signature: request ke Power Automate gagal atau timeout:", guid, error);

      return json({
        success: false,
        uncertain: true,
        message: "Respons Power Automate tidak dapat dipastikan. Jangan kirim ulang. Silakan hubungi administrator untuk memeriksa status pengiriman."
      }, 504);
    }

    if (!paResponse.ok) {
      if (isDefiniteRejection(paResponse.status)) {
        // Power Automate menolak dengan pasti: lepas reservasi agar bisa dicoba lagi.
        await releaseToActive(env, guid, lockUntil);
        reserved = false;

        return json({
          success: false,
          message: "Power Automate belum menerima pengiriman dengan sukses. Silakan coba kembali."
        }, 502);
      }

      // 5xx / 408: hasil tidak pasti, biarkan SENDING.
      console.error("signature: Power Automate membalas status tidak pasti:", guid, paResponse.status);

      return json({
        success: false,
        uncertain: true,
        message: "Power Automate membalas dengan error dan status pengiriman tidak dapat dipastikan. Jangan kirim ulang. Silakan hubungi administrator."
      }, 502);
    }

    // Power Automate sudah menerima. Tandai USED.
    // Dicoba dua kali. Jika tetap gagal, status tetap SENDING (tidak bisa
    // terkirim ulang) dan user tetap mendapat sukses karena dokumen sudah terkirim.
    let marked = false;

    for (let attempt = 0; attempt < 2 && !marked; attempt++) {
      try {
        const used = await env.DB.prepare(`
          UPDATE signing_tokens
          SET status = 'USED',
              used_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
              locked_until = NULL
          WHERE guid = ?
            AND status = 'SENDING'
        `).bind(guid).run();

        marked = Boolean(used.meta) && used.meta.changes === 1;
      } catch (error) {
        console.error("signature: gagal menandai USED (percobaan " + (attempt + 1) + "):", guid, error);
      }
    }

    if (!marked) {
      console.error("signature: dokumen terkirim tetapi status token masih SENDING, perlu dicek:", guid);
    }

    reserved = false;

    return json({ success: true, message: "Tanda tangan berhasil dikirim." });
  } catch (error) {
    console.error("signature: kesalahan server:", guid, error);

    // Lepas reservasi hanya jika error terjadi SEBELUM request ke Power Automate.
    // Jika pengiriman sudah dimulai, status SENDING dipertahankan.
    if (reserved && !sendStarted && lockUntil) {
      try {
        await releaseToActive(env, guid, lockUntil);
      } catch (releaseError) {
        console.error("signature: gagal melepas reservasi:", guid, releaseError);
      }
    }

    return json({
      success: false,
      message: "Terjadi kesalahan server saat mengirim tanda tangan."
    }, 500);
  }
}
