
const PASSWORD_ITERATIONS = 100000;
const WORLD_WIDTH = 1200;
const WORLD_HEIGHT = 800;

const json = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

const encoder = new TextEncoder();

const SKIN_TONES = ["light", "medium", "dark"];
const OUTFITS = ["casual", "formal", "worker", "sport"];

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function derivePassword(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const result = await derivePassword(password, salt, PASSWORD_ITERATIONS);
  return `${PASSWORD_ITERATIONS}.${toBase64(salt)}.${toBase64(result)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [iterationText, saltText, hashText] = stored.split(".");
    const iterations = Number(iterationText);

    if (!iterations || iterations > 1000000) return false;

    const expected = fromBase64(hashText);
    const actual = await derivePassword(
      password,
      fromBase64(saltText),
      iterations
    );

    if (actual.length !== expected.length) return false;

    let difference = 0;
    for (let i = 0; i < actual.length; i++) {
      difference |= actual[i] ^ expected[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

function makeToken() {
  return toBase64(crypto.getRandomValues(new Uint8Array(32)));
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function publicCharacter(row) {
  if (!row) return null;

  return {
    id: row.id,
    displayName: row.display_name,
    x: row.x,
    y: row.y,
    money: row.money,
    energy: row.energy,
    mood: row.mood,
    currentActivity: row.current_activity
  };
}

function publicUser(row) {
  return {
    id: row.user_id,
    username: row.username,
    email: row.email
  };
}

function authResponse(row) {
  return {
    user: publicUser(row),
    character: publicCharacter({
      id: row.character_id,
      display_name: row.display_name,
      x: row.x,
      y: row.y,
      money: row.money,
      energy: row.energy,
      mood: row.mood,
      current_activity: row.current_activity
    })
  };
}

async function createSession(db, userId) {
  const token = makeToken();
  const tokenHash = await sha256(token);

  await db.prepare(`
    INSERT INTO sessions (id, user_id, token_hash, expires_at)
    VALUES (?, ?, ?, datetime('now', '+30 days'))
  `).bind(
    crypto.randomUUID(),
    userId,
    tokenHash
  ).run();

  return token;
}

async function getSession(request, db) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!token || token.length > 200) return null;

  const tokenHash = await sha256(token);

  return db.prepare(`
    SELECT
      s.id AS session_id,
      s.user_id,
      u.username,
      u.email,
      c.id AS character_id,
      c.display_name,
      c.x,
      c.y,
      c.money,
      c.energy,
      c.mood,
      c.current_activity
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    JOIN characters c ON c.user_id = u.id
    WHERE s.token_hash = ?
      AND s.expires_at > datetime('now')
    LIMIT 1
  `).bind(tokenHash).first();
}

async function getCharacterSettings(db, characterId) {
  const row = await db.prepare(`
    SELECT character_id, bio, skin_tone, outfit, updated_at
    FROM character_settings
    WHERE character_id = ?
    LIMIT 1
  `).bind(characterId).first();

  return row || {
    character_id: characterId,
    bio: "",
    skin_tone: "medium",
    outfit: "casual",
    updated_at: null
  };
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const db = env.DB;

  if (path === "/api/health" && method === "GET") {
    return json({
      success: true,
      city: "Aurelith City",
      backend: "online",
      databaseBinding: Boolean(db)
    });
  }

  if (path === "/api/db-test" && method === "GET") {
    const result = await db.prepare(
      "SELECT 1 AS connected"
    ).first();

    return json({
      success: true,
      database: "connected",
      result
    });
  }

  // PENDAFTARAN
  if (path === "/api/register" && method === "POST") {
    const body = await readBody(request);
    if (!body) return json({ error: "Data tidak valid." }, 400);

    const username = String(body.username || "").trim().toLowerCase();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const displayName = String(body.displayName || username).trim();

    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      return json({
        error: "Username harus 3–20 karakter: huruf, angka, atau garis bawah."
      }, 400);
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return json({ error: "Masukkan alamat email yang valid." }, 400);
    }

    if (password.length < 8 || password.length > 128) {
      return json({ error: "Password harus 8–128 karakter." }, 400);
    }

    if (!displayName || displayName.length > 30) {
      return json({ error: "Nama karakter maksimal 30 karakter." }, 400);
    }

    const id = crypto.randomUUID();
    const characterId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    try {
      await db.batch([
        db.prepare(`
          INSERT INTO users (id, username, email, password_hash)
          VALUES (?, ?, ?, ?)
        `).bind(id, username, email, passwordHash),

        db.prepare(`
          INSERT INTO characters
            (id, user_id, display_name, x, y, money, energy, mood)
          VALUES (?, ?, ?, 600, 400, 1000, 100, 100)
        `).bind(characterId, id, displayName),

        db.prepare(`
          INSERT INTO character_settings
            (character_id, bio, skin_tone, outfit)
          VALUES (?, '', 'medium', 'casual')
        `).bind(characterId)
      ]);
    } catch (error) {
      const message = String(error?.message || "");

      if (/unique|constraint/i.test(message)) {
        return json({
          error: "Username atau email sudah digunakan."
        }, 409);
      }

      throw error;
    }

    const token = await createSession(db, id);

    return json({
      success: true,
      token,
      user: { id, username, email },
      character: {
        id: characterId,
        displayName,
        x: 600,
        y: 400,
        money: 1000,
        energy: 100,
        mood: 100,
        currentActivity: "idle"
      }
    }, 201);
  }

  // LOGIN
  if (path === "/api/login" && method === "POST") {
    const body = await readBody(request);
    if (!body) return json({ error: "Data tidak valid." }, 400);

    const identifier = String(body.identifier || "")
      .trim()
      .toLowerCase();
    const password = String(body.password || "");

    if (!identifier || !password || identifier.length > 254) {
      return json({ error: "Isi username/email dan password." }, 400);
    }

    const user = await db.prepare(`
      SELECT id, username, email, password_hash
      FROM users
      WHERE username = ? COLLATE NOCASE
         OR email = ? COLLATE NOCASE
      LIMIT 1
    `).bind(identifier, identifier).first();

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return json({ error: "Username/email atau password salah." }, 401);
    }

    const session = await db.prepare(`
      SELECT
        ? AS user_id,
        ? AS username,
        ? AS email,
        c.id AS character_id,
        c.display_name,
        c.x,
        c.y,
        c.money,
        c.energy,
        c.mood,
        c.current_activity
      FROM characters c
      WHERE c.user_id = ?
      LIMIT 1
    `).bind(
      user.id,
      user.username,
      user.email,
      user.id
    ).first();

    if (!session) {
      return json({
        error: "Karakter tidak ditemukan. Hubungi pengelola kota."
      }, 500);
    }

    const token = await createSession(db, user.id);

    return json({
      success: true,
      token,
      ...authResponse(session)
    });
  }

  // DAFTAR PEKERJAAN
  if (path === "/api/jobs" && method === "GET") {
    const result = await db.prepare(`
      SELECT id, name, salary, duration_minutes, location
      FROM jobs
      ORDER BY salary ASC
    `).all();

    return json({ jobs: result.results || [] });
  }

  // PROFIL AKUN DAN KARAKTER
  if (path === "/api/me" && method === "GET") {
    const session = await getSession(request, db);

    if (!session) {
      return json({ error: "Sesi berakhir. Silakan login kembali." }, 401);
    }

    return json({ success: true, ...authResponse(session) });
  }

  // KELUAR
  if (path === "/api/logout" && method === "POST") {
    const authorization = request.headers.get("Authorization") || "";
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";

    if (token && token.length <= 200) {
      await db.prepare(
        "DELETE FROM sessions WHERE token_hash = ?"
      ).bind(await sha256(token)).run();
    }

    return json({ success: true });
  }

  // PINDAHKAN KARAKTER
  if (path === "/api/move" && method === "POST") {
    const session = await getSession(request, db);
    if (!session) return json({ error: "Silakan login kembali." }, 401);

    const body = await readBody(request);
    if (!body) return json({ error: "Data lokasi tidak valid." }, 400);

    const x = Number(body.x);
    const y = Number(body.y);

    if (!Number.isFinite(x) || !Number.isFinite(y)) {
      return json({ error: "Koordinat tidak valid." }, 400);
    }

    const safeX = Math.max(25, Math.min(WORLD_WIDTH - 25, x));
    const safeY = Math.max(25, Math.min(WORLD_HEIGHT - 25, y));

    await db.prepare(`
      UPDATE characters
      SET x = ?, y = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(safeX, safeY, session.character_id).run();

    return json({ success: true, x: safeX, y: safeY });
  }

  // BEKERJA DAN MENERIMA GAJI
  if (path === "/api/work" && method === "POST") {
    const session = await getSession(request, db);
    if (!session) return json({ error: "Silakan login kembali." }, 401);

    const body = await readBody(request);
    const jobId = String(body?.jobId || "");

    if (!jobId || jobId.length > 100) {
      return json({ error: "Pilih pekerjaan yang valid." }, 400);
    }

    const job = await db.prepare(`
      SELECT id, name, salary, duration_minutes, location
      FROM jobs
      WHERE id = ?
      LIMIT 1
    `).bind(jobId).first();

    if (!job) return json({ error: "Pekerjaan tidak ditemukan." }, 404);

    const recentWork = await db.prepare(`
      SELECT id FROM activities
      WHERE character_id = ?
        AND activity_type = 'work'
        AND started_at > datetime('now', '-60 minutes')
      LIMIT 1
    `).bind(session.character_id).first();

    if (recentWork) {
      return json({
        error: "Kamu sudah bekerja dalam 60 menit terakhir. Coba lagi nanti."
      }, 429);
    }

    const transactionId = crypto.randomUUID();
    const activityId = crypto.randomUUID();

    await db.batch([
      db.prepare(`
        UPDATE characters
        SET money = money + ?,
            energy = MAX(0, energy - 15),
            current_activity = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        job.salary,
        `Bekerja: ${job.name}`,
        session.character_id
      ),

      db.prepare(`
        INSERT INTO activities
          (id, character_id, activity_type, details, status)
        VALUES (?, ?, 'work', ?, 'completed')
      `).bind(
        activityId,
        session.character_id,
        job.name
      ),

      db.prepare(`
        INSERT INTO wallet_transactions
          (id, character_id, transaction_type, amount, description)
        VALUES (?, ?, 'income', ?, ?)
      `).bind(
        transactionId,
        session.character_id,
        job.salary,
        `Gaji: ${job.name}`
      )
    ]);

    const updated = await db.prepare(`
      SELECT * FROM characters WHERE id = ?
    `).bind(session.character_id).first();

    return json({
      success: true,
      message: `Kamu memperoleh ${job.salary} uang virtual sebagai ${job.name}.`,
      job: {
        id: job.id,
        name: job.name,
        salary: job.salary,
        duration_minutes: job.duration_minutes,
        location: job.location
      },
      character: publicCharacter(updated)
    });
  }

  // DOMPET DAN RIWAYAT TRANSAKSI
  if (path === "/api/wallet" && method === "GET") {
    const session = await getSession(request, db);
    if (!session) return json({ error: "Silakan login kembali." }, 401);

    const result = await db.prepare(`
      SELECT id, transaction_type, amount, description, created_at
      FROM wallet_transactions
      WHERE character_id = ?
      ORDER BY created_at DESC, rowid DESC
      LIMIT 100
    `).bind(session.character_id).all();

    return json({
      success: true,
      balance: session.money,
      transactions: result.results || []
    });
  }

  // AMBIL PENGATURAN KARAKTER
  if (path === "/api/character-settings" && method === "GET") {
    const session = await getSession(request, db);
    if (!session) return json({ error: "Silakan login kembali." }, 401);

    const settings = await getCharacterSettings(db, session.character_id);

    return json({
      success: true,
      settings: {
        bio: settings.bio,
        skinTone: settings.skin_tone,
        outfit: settings.outfit,
        updatedAt: settings.updated_at
      }
    });
  }

  // SIMPAN BIO, WARNA KULIT, DAN PAKAIAN
  if (path === "/api/character-settings" && method === "POST") {
    const session = await getSession(request, db);
    if (!session) return json({ error: "Silakan login kembali." }, 401);

    const body = await readBody(request);
    if (!body) return json({ error: "Data pengaturan tidak valid." }, 400);

    const bio = String(body.bio ?? "").trim();
    const skinTone = String(body.skinTone ?? "medium");
    const outfit = String(body.outfit ?? "casual");

    if (bio.length > 240) {
      return json({ error: "Bio maksimal 240 karakter." }, 400);
    }

    if (!SKIN_TONES.includes(skinTone)) {
      return json({ error: "Pilihan warna kulit tidak valid." }, 400);
    }

    if (!OUTFITS.includes(outfit)) {
      return json({ error: "Pilihan pakaian tidak valid." }, 400);
    }

    await db.prepare(`
      INSERT INTO character_settings
        (character_id, bio, skin_tone, outfit, updated_at)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(character_id) DO UPDATE SET
        bio = excluded.bio,
        skin_tone = excluded.skin_tone,
        outfit = excluded.outfit,
        updated_at = CURRENT_TIMESTAMP
    `).bind(
      session.character_id,
      bio,
      skinTone,
      outfit
    ).run();

    return json({
      success: true,
      message: "Pengaturan karakter berhasil disimpan.",
      settings: {
        bio,
        skinTone,
        outfit
      }
    });
  }

  return json({ error: "Endpoint API tidak ditemukan." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    if (!env.DB) {
      return json({
        error: "Binding database DB belum dikonfigurasi."
      }, 500);
    }

    try {
      return await handleApi(request, env);
    } catch (error) {
      console.error("Aurelith API error:", error);

      return json({
        error: "Terjadi kesalahan server.",
        detail: String(error?.message || error)
      }, 500);
    }
  }
};
