
const ALLOWED_ORIGIN = "https://tandatangansuratpesanan.pages.dev";

const GUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Base64 murni PNG tanpa prefix data:image/png;base64,
const PNG_BASE64_PREFIX = "iVBORw0KGgo";
const PNG_BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

const MAX_SIGNATURE_LENGTH = 3000000;
const MAX_BODY_LENGTH = MAX_SIGNATURE_LENGTH + 10000;
const PA_TIMEOUT_MS = 20000;

// Penanda reservasi. Status D1 tetap ACTIVE, USED, atau REVOKED.
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

// 4xx selain 408 dianggap penolakan pasti.
// 408, 5xx, timeout, dan gangguan jaringan dianggap tidak pasti.
function isDefiniteRejection(status) {
  return status >= 400 && status < 500 && status !== 408;
}

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

  // Batasi ukuran request sebelum parsing JSON.
  const declaredLength = Number(request.headers.get("Content-Length"));

  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_BODY_LENGTH
  ) {
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

  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return json({
      success: false,
      message: "Request JSON tidak valid."
    }, 400);
  }

  const guid =
    typeof body.guid === "string" ? body.guid.trim() : "";

  const store =
    typeof body.store === "string" ? body.store.trim() : "";

  const docNumber =
    typeof body.docNumber === "string"
      ? body.docNumber.trim()
      : "";

  const signatureInput =
    typeof body.signature === "string"
      ? body.signature
      : "";

  // Mendukung input frontend dalam format data URL maupun Base64 murni.
  // Prefix dihapus hanya jika memang ada di awal string.
  const dataUrlPrefix = "data:image/png;base64,";

  const signature = signatureInput.startsWith(dataUrlPrefix)
    ? signatureInput.slice(dataUrlPrefix.length)
    : signatureInput;

  // Validasi format PNG Base64.
  if (
    !GUID_REGEX.test(guid) ||
    !store ||
    !docNumber ||
    signature.length > MAX_SIGNATURE_LENGTH ||
    !signature.startsWith(PNG_BASE64_PREFIX) ||
    !PNG_BASE64_REGEX.test(signature) ||
    signature.length % 4 !== 0
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
      SELECT
        guid,
        store,
        doc_number,
        expires_at,
        status,
        locked_until,
        attempt_count
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

    if (
      !Number.isFinite(expiresAtMs) ||
      now >= expiresAtMs
    ) {
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

    // Pengiriman sedang berlangsung atau hasil sebelumnya tidak pasti.
    // Jangan kirim ulang secara otomatis.
    if (token.locked_until === RESERVATION_MARKER) {
      return json({
        success: false,
        uncertain: true,
        message:
          "Pengiriman sedang diproses atau status sebelumnya belum dapat dipastikan. Jangan kirim ulang. Silakan hubungi administrator."
      }, 409);
    }

    // Periksa penguncian sementara biasa.
    if (token.locked_until) {
      const lockedUntilMs = parseDbTime(token.locked_until);

      if (
        Number.isFinite(lockedUntilMs) &&
        lockedUntilMs > now
      ) {
        return json({
          success: false,
          message: "Link dikunci sementara."
        }, 429);
      }
    }

    // Pastikan toko dan dokumen cocok dengan token di D1.
    if (
      token.store !== store ||
      token.doc_number !== docNumber
    ) {
      return json({
        success: false,
        message:
          "Data toko atau dokumen tidak cocok dengan link."
      }, 403);
    }

    const nowIso = new Date(now).toISOString();

    // Reservasi atomik menggunakan locked_until.
    // Tidak menggunakan status SENDING karena CHECK constraint D1
    // hanya mengizinkan ACTIVE, USED, dan REVOKED.
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
        message:
          "Link sedang diproses atau sudah tidak aktif."
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

        // FORMAT JSON POWER AUTOMATE TIDAK BERUBAH.
        // signature sekarang berisi Base64 murni tanpa prefix data URL.
        body: JSON.stringify({
          store,
          docNumber,
          signature
        }),

        signal: AbortSignal.timeout(PA_TIMEOUT_MS)
      });
    } catch (error) {
      // Timeout/jaringan gagal: PA mungkin sudah menerima request.
      // Pertahankan reservasi agar tidak terjadi pengiriman ulang.
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
        // Lepaskan reservasi hanya setelah penolakan pasti.
        try {
          const released = await releaseReservation(env, guid);

          reserved =
            !released.meta || released.meta.changes !== 1;
        } catch (error) {
          // Jika gagal melepas reservasi, biarkan token terkunci.
          reserved = true;

          console.error(
            "signature: gagal melepas reservasi:",
            guid,
            error
          );
        }

        return json({
          success: false,
          message:
            "Power Automate belum menerima pengiriman dengan sukses. Silakan coba kembali."
        }, 502);
      }

      // HTTP 408 atau 5xx: hasil pengiriman tidak pasti.
      // Reservasi tetap dipertahankan.
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
        `).bind(
          guid,
          RESERVATION_MARKER
        ).run();

        marked =
          Boolean(used.meta) &&
          used.meta.changes === 1;
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
      // PA sudah menerima. Jangan lepaskan reservasi jika status
      // D1 gagal diperbarui; administrator perlu memeriksanya.
      console.error(
        "signature: PA sukses tetapi token belum berstatus USED. Perlu pemeriksaan administrator:",
        guid
      );
    }

    reserved = false;

    return json({
      success: true,
      message: "Tanda tangan berhasil dikirim."
    });
  } catch (error) {
    console.error(
      "signature: kesalahan server:",
      guid,
      error
    );

    // Reservasi hanya boleh dilepas jika pengiriman ke PA
    // belum dimulai.
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
      message:
        "Terjadi kesalahan server saat mengirim tanda tangan."
    }, 500);
  }
}
