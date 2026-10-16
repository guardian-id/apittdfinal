
const ALLOWED_ORIGIN = "https://tandatangansuratpesanan.pages.dev";

const GUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const PNG_DATA_URL_PREFIX = "data:image/png;base64,iVBORw0KGgo";
const PNG_DATA_URL_REGEX = /^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/;

const MAX_SIGNATURE_LENGTH = 3000000;
const MAX_BODY_LENGTH = MAX_SIGNATURE_LENGTH + 10000;
const PA_TIMEOUT_MS = 20000;

// Penanda reservasi permanen selama pengiriman atau saat hasil tidak pasti.
// Status tabel tetap ACTIVE, USED, atau REVOKED.
// Reservasi hanya dilepas setelah penolakan pasti dari Power Automate.
const RESERVATION_MARKER = "9999-12-31T23:59:59.999Z";

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

function isDefiniteRejection(status) {
  return status >= 400 && status < 500 && status !== 408;
}

// Lepas reservasi hanya jika Power Automate menolak dengan pasti.
async function releaseReservation(env, guid) {
  return env.DB.prepare(`
    UPDATE signing_tokens
    SET locked_until = NULL
    WHERE guid = ?
      AND status = 'ACTIVE'
      AND locked_until = ?
  `).bind(guid, RESERVATION_MARKER).run();
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
    return json({
      success: false,
      message: "Origin tidak diizinkan."
    }, 403);
  }

  if (!env.DB || !env.POWER_AUTOMATE_URL) {
    return json({
      success: false,
      message: "Konfigurasi server belum lengkap."
    }, 500);
  }

  const declaredLength = Number(request.headers.get("Content-Length"));

  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_LENGTH) {
    return json({
      success: false,
      message: "Ukuran data terlalu besar."
    }, 413);
  }

  let rawBody;

  try {
    rawBody = await request.text();
  } catch {
    return json({
      success: false,
      message: "Request tidak dapat dibaca."
    }, 400);
  }

  if (rawBody.length > MAX_BODY_LENGTH) {
    return json({
      success: false,
      message: "Ukuran data terlalu besar."
    }, 413);
  }

  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({
      success: false,
      message: "Request JSON tidak valid."
    }, 400);
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({
      success: false,
      message: "Request JSON tidak valid."
    }, 400);
  }

  const guid = typeof body.guid === "string" ? body.guid.trim() : "";
  const store = typeof body.store === "string" ? body.store.trim() : "";
  const docNumber =
    typeof body.docNumber === "string" ? body.docNumber.trim() : "";
  const signature =
    typeof body.signature === "string" ? body.signature : "";

  if (
    !GUID_REGEX.test(guid) ||
    !store ||
    !docNumber ||
    signature.length > MAX_SIGNATURE_LENGTH ||
    !signature.startsWith(PNG_DATA_URL_PREFIX) ||
    !PNG_DATA_URL_REGEX.test(signature)
  ) {
    return json({
      success: false,
      message: "Data tanda tangan tidak valid."
    }, 400);
  }

  let reserved = false;
  let sendStarted = false;

  try {
    const token = await env.DB.prepare(`
      SELECT guid, store, doc_number, expires_at, status,
             locked_until, attempt_count
      FROM signing_tokens
      WHERE guid = ?
      LIMIT 1
    `).bind(guid).first();

    if (!token) {
      return json({
        success: false,
        message: "Link tidak valid atau sudah tidak berlaku."
      }, 404);
    }

    const now = Date.now();
    const expiresAtMs = parseDbTime(token.expires_at);

    if (!Number.isFinite(expiresAtMs) || now >= expiresAtMs) {
      return json({
        success: false,
        message: "Link sudah kedaluwarsa."
      }, 410);
    }

    if (token.status !== "ACTIVE") {
      return json({
        success: false,
        message: "Link sudah digunakan atau tidak aktif."
      }, 410);
    }

    // Penanda ini berarti pengiriman sedang berjalan atau hasilnya
    // tidak dapat dipastikan. Jangan pernah mengirim ulang otomatis.
    if (token.locked_until === RESERVATION_MARKER) {
      return json({
        success: false,
        uncertain: true,
        message:
          "Pengiriman sedang diproses atau status sebelumnya belum dapat dipastikan. Jangan kirim ulang. Silakan hubungi administrator."
      }, 409);
    }

    // Menghormati penguncian sementara dari data atau versi sebelumnya.
    if (token.locked_until) {
      const lockedUntilMs = parseDbTime(token.locked_until);

      if (Number.isFinite(lockedUntilMs) && lockedUntilMs > now) {
        return json({
          success: false,
          message: "Link dikunci sementara."
        }, 429);
      }
    }

    if (token.store !== store || token.doc_number !== docNumber) {
      return json({
        success: false,
        message: "Data toko atau dokumen tidak cocok dengan link."
      }, 403);
    }

    const nowIso = new Date(now).toISOString();

    // Reservasi atomik menggunakan locked_until.
    // Tidak menggunakan status SENDING karena status tersebut
    // tidak diizinkan oleh CHECK constraint tabel D1.
    const lock = await env.DB.prepare(`
      UPDATE signing_tokens
      SET locked_until = ?
      WHERE guid = ?
        AND status = 'ACTIVE'
        AND (
          locked_until IS NULL
          OR julianday(locked_until) <= julianday(?)
        )
        AND julianday(expires_at) > julianday(?)
    `).bind(
      RESERVATION_MARKER,
      guid,
      nowIso,
      nowIso
    ).run();

    if (!lock.meta || lock.meta.changes !== 1) {
      return json({
        success: false,
        message: "Link sedang diproses atau sudah tidak aktif."
      }, 409);
    }

    reserved = true;

    let paResponse;
    sendStarted = true;

    try {
      paResponse = await fetch(env.POWER_AUTOMATE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Idempotency-Key": guid
        },

        // PENTING: FORMAT JSON POWER AUTOMATE TETAP SAMA.
        body: JSON.stringify({
          store,
          docNumber,
          signature
        }),

        signal: AbortSignal.timeout(PA_TIMEOUT_MS)
      });
    } catch (error) {
      // Timeout atau gangguan jaringan: Power Automate mungkin
      // sudah menerima request. Reservasi tetap dipertahankan.
      console.error(
        "signature: request Power Automate gagal atau timeout:",
        guid,
        error
      );

      return json({
        success: false,
        uncertain: true,
        message:
          "Respons Power Automate tidak dapat dipastikan. Jangan kirim ulang. Silakan hubungi administrator untuk memeriksa status pengiriman."
      }, 504);
    }

    if (!paResponse.ok) {
      if (isDefiniteRejection(paResponse.status)) {
        // Hanya penolakan pasti yang membolehkan percobaan kembali.
        await releaseReservation(env, guid);
        reserved = false;

        return json({
          success: false,
          message:
            "Power Automate belum menerima pengiriman dengan sukses. Silakan coba kembali."
        }, 502);
      }

      // HTTP 408 dan 5xx: jangan lepas reservasi.
      console.error(
        "signature: status Power Automate tidak pasti:",
        guid,
        paResponse.status
      );

      return json({
        success: false,
        uncertain: true,
        message:
          "Power Automate membalas dengan error dan status pengiriman tidak dapat dipastikan. Jangan kirim ulang. Silakan hubungi administrator."
      }, 502);
    }

    // Power Automate membalas sukses: tandai token USED.
    // Jika pembaruan gagal, reservasi tetap terkunci agar request
    // yang sama tidak dikirim ulang.
    let marked = false;

    for (let attempt = 0; attempt < 2 && !marked; attempt++) {
      try {
        const used = await env.DB.prepare(`
          UPDATE signing_tokens
          SET status = 'USED',
              used_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
              locked_until = NULL
          WHERE guid = ?
            AND status = 'ACTIVE'
            AND locked_until = ?
        `).bind(guid, RESERVATION_MARKER).run();

        marked = Boolean(used.meta) && used.meta.changes === 1;
      } catch (error) {
        console.error(
          "signature: gagal menandai USED, percobaan " +
            (attempt + 1) + ":",
          guid,
          error
        );
      }
    }

    if (!marked) {
      console.error(
        "signature: Power Automate membalas sukses tetapi status D1 belum USED. Perlu pemeriksaan administrator:",
        guid
      );
    }

    reserved = false;

    return json({
      success: true,
      message: "Tanda tangan berhasil dikirim."
    });
  } catch (error) {
    console.error("signature: kesalahan server:", guid, error);

    // Reservasi hanya dilepas jika error terjadi sebelum request
    // ke Power Automate dimulai.
    if (reserved && !sendStarted) {
      try {
        await releaseReservation(env, guid);
      } catch (releaseError) {
        console.error(
          "signature: gagal melepas reservasi:",
          guid,
          releaseError
        );
      }
    }

    return json({
      success: false,
      message: "Terjadi kesalahan server saat mengirim tanda tangan."
    }, 500);
  }
}
