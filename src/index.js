
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

  if (path === "/api/realtime" && method === "GET") {
    if (!env.REALTIME) return json({ error: "Durable Object REALTIME belum dikonfigurasi." }, 503);
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return json({ error: "WebSocket upgrade diperlukan." }, 426);
    }
    // Authenticate with a WebSocket subprotocol instead of a URL query, keeping the session token out of request URLs.
    const offeredProtocols = (request.headers.get("Sec-WebSocket-Protocol") || "").split(",").map(v => v.trim());
    const authProtocol = offeredProtocols.find(v => v.startsWith("bearer."));
    const wsToken = authProtocol ? authProtocol.slice(7) : "";
    if (!wsToken || wsToken.length > 200) return json({ error: "Sesi WebSocket tidak valid." }, 401);
    const sessionRequest = new Request("https://session.internal/", {
      headers: { "Authorization": "Bearer " + wsToken }
    });
    const session = await getSession(sessionRequest, db);
    if (!session) return json({ error: "Silakan login kembali." }, 401);
    const id = env.REALTIME.idFromName("aurelith-city-world");
    const stub = env.REALTIME.get(id);
    const headers = new Headers(request.headers);
    headers.set("X-Aurelith-Character-Id", session.character_id);
    headers.set("X-Aurelith-Display-Name", session.display_name || "Warga");
    headers.set("X-Aurelith-X", String(session.x ?? 600));
    headers.set("X-Aurelith-Y", String(session.y ?? 400));
    return stub.fetch(new Request("https://realtime.internal/connect", {
      method: "GET", headers
    }));
  }

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

    await db.batch([
      db.prepare(`
        UPDATE characters
        SET x = ?, y = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(safeX, safeY, session.character_id),
      db.prepare(`CREATE TABLE IF NOT EXISTS player_presence (
        character_id TEXT PRIMARY KEY,
        x REAL NOT NULL DEFAULT 600,
        y REAL NOT NULL DEFAULT 400,
        last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`),
      db.prepare(`
        INSERT INTO player_presence (character_id, x, y, last_seen)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(character_id) DO UPDATE SET
          x = excluded.x, y = excluded.y, last_seen = CURRENT_TIMESTAMP
      `).bind(session.character_id, safeX, safeY)
    ]);

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


  // SISTEM GAMEPLAY TAMBAHAN — tabel baru dibuat secara additive.
  // Tidak menghapus atau mengubah tabel/data akun, pekerjaan, atau dompet yang sudah ada.
  if (path.startsWith("/api/game/")) {
    const session = await getSession(request, db);
    if (!session) return json({ error: "Sesi berakhir. Silakan login kembali." }, 401);

    await db.batch([
      db.prepare(`
        CREATE TABLE IF NOT EXISTS character_game_state (
          character_id TEXT PRIMARY KEY,
          health INTEGER NOT NULL DEFAULT 100,
          wanted_level INTEGER NOT NULL DEFAULT 0,
          activity_type TEXT,
          activity_started_at TEXT,
          activity_ends_at TEXT,
          activity_reward INTEGER NOT NULL DEFAULT 0,
          last_crime_at TEXT,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
        )
      `),
      db.prepare(`
        CREATE TABLE IF NOT EXISTS character_inventory (
          id TEXT PRIMARY KEY,
          character_id TEXT NOT NULL,
          item_key TEXT NOT NULL,
          item_name TEXT NOT NULL,
          quantity INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(character_id, item_key),
          FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
        )
      `),
      db.prepare("CREATE INDEX IF NOT EXISTS idx_game_state_activity_end ON character_game_state(activity_ends_at)"),
      db.prepare("CREATE INDEX IF NOT EXISTS idx_inventory_character ON character_inventory(character_id)"),
      db.prepare(`CREATE TABLE IF NOT EXISTS character_skills (
        character_id TEXT NOT NULL,
        skill_key TEXT NOT NULL,
        xp INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(character_id, skill_key),
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`),
      db.prepare("CREATE INDEX IF NOT EXISTS idx_skills_character ON character_skills(character_id)")
    ]);

    await db.prepare(`
      INSERT OR IGNORE INTO character_game_state (character_id)
      VALUES (?)
    `).bind(session.character_id).run();

    const settleFinishedActivity = async () => {
      const state = await db.prepare(`
        SELECT activity_type, activity_started_at, activity_ends_at, activity_reward
        FROM character_game_state WHERE character_id = ? LIMIT 1
      `).bind(session.character_id).first();

      if (!state?.activity_type || !state.activity_ends_at) return null;
      const due = await db.prepare("SELECT datetime(?) <= datetime('now') AS ready")
        .bind(state.activity_ends_at).first();
      if (!due?.ready) return null;

      const clear = await db.prepare(`
        UPDATE character_game_state
        SET activity_type = NULL, activity_started_at = NULL,
            activity_ends_at = NULL, activity_reward = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE character_id = ? AND activity_type = ? AND activity_ends_at = ?
      `).bind(session.character_id, state.activity_type, state.activity_ends_at).run();

      if (!clear.meta?.changes) return null;
      const minutes = Math.max(1, Math.round((Date.parse(state.activity_ends_at + "Z") - Date.parse(state.activity_started_at + "Z")) / 60000) || 60);
      let reward = Math.max(0, Number(state.activity_reward) || 0);
      await db.prepare(`
        UPDATE activities
        SET status = 'completed',
            details = details || ' · selesai'
        WHERE character_id = ? AND activity_type = ? AND status = 'in_progress'
      `).bind(session.character_id, state.activity_type).run();
      if (state.activity_type === "rest") {
        await db.prepare(`
          UPDATE characters SET energy = MIN(100, energy + ?),
            mood = MIN(100, mood + 8), current_activity = 'Santai',
            updated_at = CURRENT_TIMESTAMP WHERE id = ?
        `).bind(Math.min(60, Math.ceil(minutes / 10)), session.character_id).run();
        return { type: "rest", reward: 0, message: "Waktu istirahat selesai. Energi dan suasana hati pulih." };
      }

      if (state.activity_type === "side_job" || state.activity_type === "volunteer") {
        const transactionId = crypto.randomUUID();
        const label = state.activity_type === "volunteer" ? "Kegiatan sukarela" : "Pekerjaan sampingan offline";
        const energyCost = state.activity_type === "volunteer" ? 5 : 10;
        await db.batch([
          db.prepare(`UPDATE characters SET money = money + ?, energy = MAX(0, energy - ?),
            mood = MIN(100, mood + ?), current_activity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(reward, energyCost, state.activity_type === "volunteer" ? 5 : 0, label + " selesai", session.character_id),
          db.prepare(`INSERT INTO wallet_transactions (id, character_id, transaction_type, amount, description)
            VALUES (?, ?, 'income', ?, ?)`).bind(transactionId, session.character_id, reward, label + " selesai"),
          db.prepare(`INSERT INTO activities (id, character_id, activity_type, details, status)
            VALUES (?, ?, ?, ?, 'completed')`).bind(crypto.randomUUID(), session.character_id, state.activity_type, label + " selesai")
        ]);
        return { type: state.activity_type, reward, message: label + " selesai. Pendapatan sudah masuk ke dompet." };
      }
      const skillForActivity = { training: "fitness", study: "knowledge", craft: "crafting" }[state.activity_type];
      if (skillForActivity) {
        const xp = Math.max(5, Math.round(minutes / 5));
        const skillLabel = { fitness: "Kebugaran", knowledge: "Pengetahuan", crafting: "Keterampilan" }[skillForActivity];
        const energyCost = state.activity_type === "training" ? Math.min(35, Math.ceil(minutes / 4)) : state.activity_type === "craft" ? Math.min(20, Math.ceil(minutes / 8)) : Math.min(12, Math.ceil(minutes / 12));
        await db.batch([
          db.prepare(`INSERT INTO character_skills (character_id, skill_key, xp)
            VALUES (?, ?, ?) ON CONFLICT(character_id, skill_key)
            DO UPDATE SET xp = character_skills.xp + excluded.xp, updated_at = CURRENT_TIMESTAMP`)
            .bind(session.character_id, skillForActivity, xp),
          db.prepare(`UPDATE characters SET energy = MAX(0, energy - ?), mood = MIN(100, mood + ?),
            current_activity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(energyCost, state.activity_type === "study" ? 4 : 2, skillLabel + " meningkat", session.character_id),
          db.prepare(`INSERT INTO activities (id, character_id, activity_type, details, status)
            VALUES (?, ?, ?, ?, 'completed')`)
            .bind(crypto.randomUUID(), session.character_id, state.activity_type, skillLabel + " meningkat +" + xp + " XP")
        ]);
        return { type: state.activity_type, reward: 0, xp, skill: skillForActivity, message: skillLabel + " meningkat +" + xp + " XP." };
      }
      return null;
    };

    const settleResult = await settleFinishedActivity();

    if (path === "/api/game/state" && method === "GET") {
      const [state, characterRow, inventory, recentActivities, skills] = await Promise.all([
        db.prepare("SELECT * FROM character_game_state WHERE character_id = ?").bind(session.character_id).first(),
        db.prepare("SELECT money, energy, mood, current_activity FROM characters WHERE id = ?").bind(session.character_id).first(),
        db.prepare("SELECT item_key, item_name, quantity FROM character_inventory WHERE character_id = ? AND quantity > 0 ORDER BY item_name").bind(session.character_id).all(),
        db.prepare("SELECT activity_type, details, status, started_at FROM activities WHERE character_id = ? ORDER BY started_at DESC LIMIT 12").bind(session.character_id).all(),
        db.prepare("SELECT skill_key, xp FROM character_skills WHERE character_id = ? ORDER BY skill_key").bind(session.character_id).all()
      ]);
      return json({
        success: true,
        state: {
          health: state?.health ?? 100,
          wantedLevel: state?.wanted_level ?? 0,
          activityType: state?.activity_type ?? null,
          activityStartedAt: state?.activity_started_at ?? null,
          activityEndsAt: state?.activity_ends_at ?? null,
          activityReward: state?.activity_reward ?? 0,
          lastCrimeAt: state?.last_crime_at ?? null
        },
        character: characterRow,
        inventory: inventory.results || [],
        activities: recentActivities.results || [],
        skills: skills.results || [],
        settledActivity: settleResult
      });
    }

    if (path === "/api/game/activity/start" && method === "POST") {
      const body = await readBody(request);
      const activityType = String(body?.activityType || "");
      const hours = Number(body?.hours || 1);
      const activityTypes = ["rest", "side_job", "training", "study", "volunteer", "craft"];
      if (!activityTypes.includes(activityType)) {
        return json({ error: "Jenis aktivitas tidak dikenal." }, 400);
      }
      if (!Number.isInteger(hours) || hours < 1 || hours > 8) {
        return json({ error: "Durasi harus 1–8 jam." }, 400);
      }
      const current = await db.prepare("SELECT activity_type, activity_ends_at FROM character_game_state WHERE character_id = ?")
        .bind(session.character_id).first();
      if (current?.activity_type) {
        return json({ error: "Karakter sedang menjalankan aktivitas. Tunggu sampai selesai atau klaim hasilnya." }, 409);
      }
      const energyRequired = activityType === "side_job" ? 10 : activityType === "training" ? 20 : activityType === "study" ? 8 : activityType === "craft" ? 15 : 0;
      if (Number(session.energy) < energyRequired) return json({ error: "Energi tidak cukup untuk aktivitas ini." }, 400);
      const reward = activityType === "side_job" ? hours * 100 : activityType === "volunteer" ? hours * 35 : 0;
      await db.prepare(`
        UPDATE character_game_state
        SET activity_type = ?, activity_started_at = CURRENT_TIMESTAMP,
            activity_ends_at = datetime('now', '+' || ? || ' hours'),
            activity_reward = ?, updated_at = CURRENT_TIMESTAMP
        WHERE character_id = ? AND activity_type IS NULL
      `).bind(activityType, hours, reward, session.character_id).run();
      await db.prepare("UPDATE characters SET current_activity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(({rest:"Istirahat offline",side_job:"Pekerjaan sampingan offline",training:"Latihan kebugaran",study:"Belajar",volunteer:"Kegiatan sukarela",craft:"Mengerjakan kerajinan"})[activityType], session.character_id).run();
      await db.prepare(`
        INSERT INTO activities (id, character_id, activity_type, details, status)
        VALUES (?, ?, ?, ?, 'in_progress')
      `).bind(crypto.randomUUID(), session.character_id, activityType,
        ({rest:"Istirahat selama ",side_job:"Pekerjaan sampingan selama ",training:"Latihan kebugaran selama ",study:"Belajar selama ",volunteer:"Kegiatan sukarela selama ",craft:"Mengerjakan kerajinan selama "}[activityType]) + hours + " jam").run();
      return json({
        success: true,
        message: ({rest:"Istirahat dimulai. Energi pulih setelah durasi selesai.",side_job:"Pekerjaan sampingan dimulai. Pendapatan diberikan saat selesai.",training:"Latihan dimulai. Kebugaran bertambah saat selesai.",study:"Belajar dimulai. Pengetahuan bertambah saat selesai.",volunteer:"Kegiatan sukarela dimulai. Kamu mendapat uang saku dan mood.",craft:"Kegiatan kerajinan dimulai. Keterampilan bertambah saat selesai."})[activityType],
        activityType, hours, reward, endsAt: new Date(Date.now() + hours * 3600000).toISOString()
      }, 201);
    }

    if (path === "/api/game/crime" && method === "POST") {
      const body = await readBody(request);
      const crimeType = String(body?.crimeType || "");
      const crimes = {
        pickpocket: { label: "Mencopet", chance: 0.58, min: 80, max: 220, fine: 100 },
        shoplift: { label: "Mencuri barang toko", chance: 0.48, min: 140, max: 360, fine: 180 },
        heist: { label: "Perampokan berisiko", chance: 0.30, min: 350, max: 800, fine: 400 }
      };
      const crime = crimes[crimeType];
      if (!crime) return json({ error: "Aksi kriminal tidak dikenal." }, 400);
      const state = await db.prepare("SELECT * FROM character_game_state WHERE character_id = ?").bind(session.character_id).first();
      if (Number(state?.wanted_level || 0) >= 5) return json({ error: "Tingkat buronan maksimal. Tunggu sampai buronan berkurang sebelum mencoba lagi." }, 429);
      const recent = await db.prepare(`
        SELECT id FROM activities WHERE character_id = ? AND activity_type = 'crime'
          AND started_at > datetime('now', '-10 minutes') LIMIT 1
      `).bind(session.character_id).first();
      if (recent) return json({ error: "Kamu perlu menunggu 10 menit sebelum mencoba aksi kriminal lagi." }, 429);
      if (Number(session.energy) < 15) return json({ error: "Energi minimal 15 diperlukan." }, 400);

      const success = Math.random() < crime.chance;
      const amount = success
        ? Math.floor(crime.min + Math.random() * (crime.max - crime.min + 1))
        : Math.min(Number(session.money) || 0, crime.fine);
      const wanted = Math.min(5, Math.max(0, Number(state?.wanted_level || 0) + (success ? 1 : 2)));
      const details = success
        ? crime.label + " berhasil; memperoleh " + amount + " uang virtual"
        : crime.label + " gagal; denda " + amount + " uang virtual";
      const statements = [
        db.prepare(`UPDATE characters SET money = MAX(0, money + ?), energy = MAX(0, energy - 15),
          mood = MAX(0, mood - 5), current_activity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
          .bind(success ? amount : -amount, success ? "Melakukan aksi kriminal" : "Tertangkap saat beraksi", session.character_id),
        db.prepare(`UPDATE character_game_state SET wanted_level = ?, last_crime_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP WHERE character_id = ?`).bind(wanted, session.character_id),
        db.prepare(`INSERT INTO activities (id, character_id, activity_type, details, status)
          VALUES (?, ?, 'crime', ?, ?)`).bind(crypto.randomUUID(), session.character_id, details, success ? "completed" : "failed")
      ];
      if (amount > 0) {
        statements.push(db.prepare(`INSERT INTO wallet_transactions
          (id, character_id, transaction_type, amount, description)
          VALUES (?, ?, ?, ?, ?)`).bind(crypto.randomUUID(), session.character_id,
          success ? "income" : "expense", amount, success ? "Hasil kriminal: " + crime.label : "Denda kriminal: " + crime.label));
      }
      await db.batch(statements);
      const updated = await db.prepare("SELECT money, energy, mood, current_activity FROM characters WHERE id = ?").bind(session.character_id).first();
      return json({
        success: true, outcome: success ? "success" : "caught", amount, wantedLevel: wanted,
        message: success
          ? "Berhasil: " + details + ". Tingkat buronan meningkat."
          : "Gagal: " + details + ". Tingkat buronan meningkat lebih besar.",
        character: { ...updated }
      });
    }


    if (path === "/api/game/shop" && method === "GET") {
      return json({
        success: true,
        items: [
          { key: "meal", name: "Paket Makan", price: 60, description: "Memulihkan 15 energi dan 5 suasana hati.", effect: "energy+15,mood+5" },
          { key: "energy_drink", name: "Minuman Energi", price: 80, description: "Memulihkan hingga 25 energi.", effect: "energy+25" },
          { key: "first_aid", name: "Kotak P3K", price: 150, description: "Memulihkan hingga 30 kesehatan.", effect: "health+30" }
        ]
      });
    }

    if (path === "/api/game/shop" && method === "POST") {
      const body = await readBody(request);
      const catalog = {
        meal: { name: "Paket Makan", price: 60 },
        energy_drink: { name: "Minuman Energi", price: 80 },
        first_aid: { name: "Kotak P3K", price: 150 }
      };
      const itemKey = String(body?.itemKey || "");
      const item = catalog[itemKey];
      if (!item) return json({ error: "Barang tidak tersedia di toko." }, 400);
      const buyer = await db.prepare("SELECT money FROM characters WHERE id = ?").bind(session.character_id).first();
      if (!buyer || Number(buyer.money) < item.price) {
        return json({ error: "Saldo tidak cukup untuk membeli barang ini." }, 400);
      }
      const inventoryId = crypto.randomUUID();
      const transactionId = crypto.randomUUID();
      const purchase = await db.batch([
        db.prepare("UPDATE characters SET money = money - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND money >= ?")
          .bind(item.price, session.character_id, item.price),
        db.prepare(`INSERT INTO character_inventory (id, character_id, item_key, item_name, quantity)
          VALUES (?, ?, ?, ?, 1)
          ON CONFLICT(character_id, item_key) DO UPDATE SET
          quantity = character_inventory.quantity + 1, updated_at = CURRENT_TIMESTAMP`)
          .bind(inventoryId, session.character_id, itemKey, item.name),
        db.prepare(`INSERT INTO wallet_transactions
          (id, character_id, transaction_type, amount, description)
          VALUES (?, ?, 'expense', ?, ?)`)
          .bind(transactionId, session.character_id, item.price, "Pembelian: " + item.name),
        db.prepare(`INSERT INTO activities (id, character_id, activity_type, details, status)
          VALUES (?, ?, 'purchase', ?, 'completed')`)
          .bind(crypto.randomUUID(), session.character_id, "Membeli " + item.name)
      ]);
      const balance = await db.prepare("SELECT money FROM characters WHERE id = ?").bind(session.character_id).first();
      return json({ success: true, message: item.name + " berhasil dibeli.", item: { key: itemKey, name: item.name }, balance: balance?.money ?? 0 }, 201);
    }

    if (path === "/api/game/use-item" && method === "POST") {
      const body = await readBody(request);
      const itemKey = String(body?.itemKey || "");
      const inventoryItem = await db.prepare(`
        SELECT id, quantity, item_name FROM character_inventory
        WHERE character_id = ? AND item_key = ? AND quantity > 0 LIMIT 1
      `).bind(session.character_id, itemKey).first();
      if (!inventoryItem) return json({ error: "Barang itu tidak ada di inventarismu." }, 404);

      await db.prepare("INSERT OR IGNORE INTO character_game_state (character_id) VALUES (?)")
        .bind(session.character_id).run();
      if (itemKey === "meal") {
        await db.batch([
          db.prepare("UPDATE characters SET energy = MIN(100, energy + 15), mood = MIN(100, mood + 5), updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(session.character_id),
          db.prepare("UPDATE character_inventory SET quantity = quantity - 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND quantity > 0").bind(inventoryItem.id)
        ]);
      } else if (itemKey === "energy_drink") {
        await db.batch([
          db.prepare("UPDATE characters SET energy = MIN(100, energy + 25), updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(session.character_id),
          db.prepare("UPDATE character_inventory SET quantity = quantity - 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND quantity > 0").bind(inventoryItem.id)
        ]);
      } else if (itemKey === "first_aid") {
        await db.batch([
          db.prepare("UPDATE character_game_state SET health = MIN(100, health + 30), updated_at = CURRENT_TIMESTAMP WHERE character_id = ?").bind(session.character_id),
          db.prepare("UPDATE character_inventory SET quantity = quantity - 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND quantity > 0").bind(inventoryItem.id)
        ]);
      } else {
        return json({ error: "Barang ini belum bisa digunakan." }, 400);
      }

      await db.prepare(`INSERT INTO activities (id, character_id, activity_type, details, status)
        VALUES (?, ?, 'item_use', ?, 'completed')`).bind(crypto.randomUUID(), session.character_id, "Menggunakan " + inventoryItem.item_name).run();
      const updated = await db.prepare("SELECT money, energy, mood, current_activity FROM characters WHERE id = ?").bind(session.character_id).first();
      const state = await db.prepare("SELECT health FROM character_game_state WHERE character_id = ?").bind(session.character_id).first();
      return json({ success: true, message: inventoryItem.item_name + " digunakan.", character: updated, health: state?.health ?? 100 });
    }

    if (path === "/api/game/lay-low" && method === "POST") {
      const state = await db.prepare("SELECT wanted_level FROM character_game_state WHERE character_id = ?").bind(session.character_id).first();
      if (!Number(state?.wanted_level || 0)) return json({ success: true, message: "Kamu tidak sedang diburu." });
      const recent = await db.prepare(`
        SELECT id FROM activities WHERE character_id = ? AND activity_type = 'lay_low'
          AND started_at > datetime('now', '-30 minutes') LIMIT 1
      `).bind(session.character_id).first();
      if (recent) return json({ error: "Kamu sudah bersembunyi. Coba lagi setelah 30 menit." }, 429);
      await db.batch([
        db.prepare("UPDATE character_game_state SET wanted_level = MAX(0, wanted_level - 1), updated_at = CURRENT_TIMESTAMP WHERE character_id = ?").bind(session.character_id),
        db.prepare("UPDATE characters SET current_activity = 'Bersembunyi', energy = MAX(0, energy - 5), updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(session.character_id),
        db.prepare("INSERT INTO activities (id, character_id, activity_type, details, status) VALUES (?, ?, 'lay_low', 'Bersembunyi untuk menurunkan tingkat buronan', 'completed')").bind(crypto.randomUUID(), session.character_id)
      ]);
      return json({ success: true, message: "Kamu bersembunyi dan menurunkan tingkat buronan satu tingkat." });
    }

    return json({ error: "Endpoint gameplay tidak ditemukan." }, 404);
  }


  // MULTIPLAYER SOCIAL: presence, player discovery, chat, and friend requests.
  if (path.startsWith("/api/social/")) {
    const session = await getSession(request, db);
    if (!session) return json({ error: "Sesi berakhir. Silakan login kembali." }, 401);

    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS player_presence (
        character_id TEXT PRIMARY KEY,
        x REAL NOT NULL DEFAULT 600,
        y REAL NOT NULL DEFAULT 400,
        last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS social_messages (
        id TEXT PRIMARY KEY,
        sender_character_id TEXT NOT NULL,
        recipient_character_id TEXT,
        channel TEXT NOT NULL CHECK(channel IN ('global','local','whisper')),
        message TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(recipient_character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS player_friendships (
        id TEXT PRIMARY KEY,
        requester_character_id TEXT NOT NULL,
        addressee_character_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(requester_character_id, addressee_character_id),
        CHECK(requester_character_id <> addressee_character_id),
        FOREIGN KEY(requester_character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(addressee_character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`),
      db.prepare("CREATE INDEX IF NOT EXISTS idx_social_messages_created ON social_messages(channel, created_at)"),
      db.prepare("CREATE INDEX IF NOT EXISTS idx_social_presence_seen ON player_presence(last_seen)")
    ]);

    await db.prepare(`
      INSERT INTO player_presence (character_id, x, y, last_seen)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(character_id) DO UPDATE SET
        x = excluded.x, y = excluded.y, last_seen = CURRENT_TIMESTAMP
    `).bind(session.character_id, session.x, session.y).run();

    if (path === "/api/social/presence" && method === "POST") {
      return json({ success: true, lastSeen: new Date().toISOString() });
    }

    if (path === "/api/social/players" && method === "GET") {
      const result = await db.prepare(`
        SELECT c.id AS characterId, c.display_name AS displayName,
          c.x, c.y, c.current_activity AS currentActivity,
          cs.bio, cs.outfit,
          CASE WHEN p.last_seen >= datetime('now', '-2 minutes') THEN 1 ELSE 0 END AS online,
          p.last_seen AS lastSeen,
          CASE WHEN f1.status = 'accepted' OR f2.status = 'accepted' THEN 1 ELSE 0 END AS isFriend,
          CASE WHEN f1.status = 'pending' AND f1.addressee_character_id = ? THEN 'incoming'
               WHEN f2.status = 'pending' AND f2.requester_character_id = ? THEN 'outgoing'
               ELSE NULL END AS friendRequest
        FROM characters c
        LEFT JOIN player_presence p ON p.character_id = c.id
        LEFT JOIN character_settings cs ON cs.character_id = c.id
        LEFT JOIN player_friendships f1 ON f1.requester_character_id = c.id AND f1.addressee_character_id = ?
        LEFT JOIN player_friendships f2 ON f2.requester_character_id = ? AND f2.addressee_character_id = c.id
        WHERE c.id <> ?
        ORDER BY online DESC, c.display_name COLLATE NOCASE ASC
        LIMIT 80
      `).bind(session.character_id, session.character_id, session.character_id, session.character_id, session.character_id).all();
      return json({ success: true, players: result.results || [] });
    }

    if (path === "/api/social/messages" && method === "GET") {
      const channel = String(url.searchParams.get("channel") || "global");
      const before = String(url.searchParams.get("before") || "");
      if (!["global","local","whisper"].includes(channel)) return json({ error: "Channel chat tidak valid." }, 400);
      let query, args;
      if (channel === "whisper") {
        const target = String(url.searchParams.get("target") || "");
        if (!target) return json({ error: "Pilih pemain untuk pesan pribadi." }, 400);
        query = `
          SELECT m.id, m.channel, m.message, m.created_at AS createdAt,
            m.sender_character_id AS senderCharacterId,
            sender.display_name AS senderName,
            m.recipient_character_id AS recipientCharacterId,
            recipient.display_name AS recipientName
          FROM social_messages m
          JOIN characters sender ON sender.id = m.sender_character_id
          JOIN characters recipient ON recipient.id = m.recipient_character_id
          WHERE m.channel = 'whisper'
            AND ((m.sender_character_id = ? AND m.recipient_character_id = ?)
              OR (m.sender_character_id = ? AND m.recipient_character_id = ?))
            AND (? = '' OR m.created_at < ?)
          ORDER BY m.created_at DESC LIMIT 50
        `;
        args = [session.character_id, target, target, session.character_id, before, before];
      } else {
        query = `
          SELECT m.id, m.channel, m.message, m.created_at AS createdAt,
            m.sender_character_id AS senderCharacterId,
            c.display_name AS senderName
          FROM social_messages m JOIN characters c ON c.id = m.sender_character_id
          WHERE m.channel = ? AND (? = '' OR m.created_at < ?)
            AND (? <> 'local' OR (
              EXISTS (SELECT 1 FROM player_presence p
                WHERE p.character_id = m.sender_character_id
                AND p.last_seen >= datetime('now', '-2 minutes')
                AND ((p.x - ?) * (p.x - ?) + (p.y - ?) * (p.y - ?)) <= 62500)
            ))
          ORDER BY m.created_at DESC LIMIT 50
        `;
        args = [channel, before, before, channel, session.x, session.x, session.y, session.y];
      }
      const result = await db.prepare(query).bind(...args).all();
      return json({ success: true, messages: (result.results || []).reverse() });
    }

    if (path === "/api/social/messages" && method === "POST") {
      const body = await readBody(request);
      const channel = String(body?.channel || "global");
      const message = String(body?.message || "").trim();
      const target = String(body?.targetCharacterId || "");
      if (!["global","local","whisper"].includes(channel)) return json({ error: "Channel chat tidak valid." }, 400);
      if (!message || message.length > 500) return json({ error: "Pesan harus 1–500 karakter." }, 400);
      if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(message)) return json({ error: "Pesan berisi karakter yang tidak diizinkan." }, 400);
      let recipient = null;
      if (channel === "whisper") {
        if (!target || target === session.character_id) return json({ error: "Pilih pemain lain untuk pesan pribadi." }, 400);
        recipient = await db.prepare("SELECT id FROM characters WHERE id = ?").bind(target).first();
        if (!recipient) return json({ error: "Pemain tidak ditemukan." }, 404);
      }
      if (channel === "local") {
        const nearby = await db.prepare(`
          SELECT character_id FROM player_presence
          WHERE character_id = ? AND last_seen >= datetime('now', '-2 minutes')
            AND ((x - ?) * (x - ?) + (y - ?) * (y - ?)) <= 62500
        `).bind(session.character_id, session.x, session.x, session.y, session.y).first();
        if (!nearby) return json({ error: "Perbarui posisi sebelum mengirim chat lokal." }, 409);
      }
      const id = crypto.randomUUID();
      await db.prepare(`
        INSERT INTO social_messages (id, sender_character_id, recipient_character_id, channel, message)
        VALUES (?, ?, ?, ?, ?)
      `).bind(id, session.character_id, recipient?.id || null, channel, message).run();
      return json({ success: true, message: { id, channel, message, senderCharacterId: session.character_id, senderName: session.display_name, recipientCharacterId: recipient?.id || null, createdAt: new Date().toISOString() } }, 201);
    }

    if (path === "/api/social/friends" && method === "GET") {
      const result = await db.prepare(`
        SELECT f.id AS requestId, f.status, f.created_at AS createdAt,
          CASE WHEN f.requester_character_id = ? THEN f.addressee_character_id ELSE f.requester_character_id END AS characterId,
          c.display_name AS displayName,
          CASE WHEN f.requester_character_id = ? THEN 'outgoing' ELSE 'incoming' END AS direction
        FROM player_friendships f
        JOIN characters c ON c.id = CASE WHEN f.requester_character_id = ? THEN f.addressee_character_id ELSE f.requester_character_id END
        WHERE f.requester_character_id = ? OR f.addressee_character_id = ?
        ORDER BY CASE f.status WHEN 'pending' THEN 0 ELSE 1 END, f.created_at DESC
        LIMIT 100
      `).bind(session.character_id, session.character_id, session.character_id, session.character_id, session.character_id).all();
      return json({ success: true, friends: result.results || [] });
    }

    if (path === "/api/social/friends/request" && method === "POST") {
      const body = await readBody(request);
      const target = String(body?.targetCharacterId || "");
      if (!target || target === session.character_id) return json({ error: "Target teman tidak valid." }, 400);
      const exists = await db.prepare("SELECT id FROM characters WHERE id = ?").bind(target).first();
      if (!exists) return json({ error: "Pemain tidak ditemukan." }, 404);
      const reverse = await db.prepare("SELECT id, status FROM player_friendships WHERE requester_character_id = ? AND addressee_character_id = ?").bind(target, session.character_id).first();
      if (reverse?.status === "accepted") return json({ error: "Kalian sudah berteman." }, 409);
      if (reverse?.status === "pending") {
        await db.prepare("UPDATE player_friendships SET status = 'accepted', updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(reverse.id).run();
        return json({ success: true, message: "Permintaan pertemanan diterima. Kalian sekarang berteman." });
      }
      const existing = await db.prepare("SELECT id, status FROM player_friendships WHERE requester_character_id = ? AND addressee_character_id = ?").bind(session.character_id, target).first();
      if (existing?.status === "accepted") return json({ error: "Kalian sudah berteman." }, 409);
      if (existing?.status === "pending") return json({ error: "Permintaan pertemanan sudah dikirim." }, 409);
      await db.prepare(`
        INSERT INTO player_friendships (id, requester_character_id, addressee_character_id, status)
        VALUES (?, ?, ?, 'pending')
        ON CONFLICT(requester_character_id, addressee_character_id) DO UPDATE SET status = 'pending', updated_at = CURRENT_TIMESTAMP
      `).bind(crypto.randomUUID(), session.character_id, target).run();
      return json({ success: true, message: "Permintaan pertemanan terkirim." }, 201);
    }

    if (path === "/api/social/friends/respond" && method === "POST") {
      const body = await readBody(request);
      const requestId = String(body?.requestId || "");
      const accept = body?.accept === true;
      const result = await db.prepare(`
        UPDATE player_friendships
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND addressee_character_id = ? AND status = 'pending'
      `).bind(accept ? "accepted" : "declined", requestId, session.character_id).run();
      if (!result.meta?.changes) return json({ error: "Permintaan tidak ditemukan atau sudah diproses." }, 404);
      return json({ success: true, message: accept ? "Permintaan pertemanan diterima." : "Permintaan pertemanan ditolak." });
    }


    if (path === "/api/social/transfer" && method === "POST") {
      const body = await readBody(request);
      const targetId = String(body?.targetCharacterId || "");
      const amount = Number(body?.amount);
      const description = String(body?.description || "Transfer antarpemain").trim().slice(0, 80) || "Transfer antarpemain";
      if (!targetId || targetId === session.character_id) return json({ error: "Pilih pemain lain sebagai penerima." }, 400);
      if (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000) return json({ error: "Nominal harus berupa bilangan bulat antara 1 dan 100.000." }, 400);
      const recipient = await db.prepare("SELECT id, display_name FROM characters WHERE id = ?").bind(targetId).first();
      if (!recipient) return json({ error: "Pemain penerima tidak ditemukan." }, 404);
      const transferId = crypto.randomUUID();
      const senderLedgerId = crypto.randomUUID();
      const receiverLedgerId = crypto.randomUUID();
      const result = await db.batch([
        db.prepare("UPDATE characters SET money = money - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND money >= ?")
          .bind(amount, session.character_id, amount),
        db.prepare(`INSERT INTO wallet_transactions (id, character_id, transaction_type, amount, description)
          SELECT ?, ?, 'expense', ?, ? WHERE changes() > 0`)
          .bind(senderLedgerId, session.character_id, amount, "Transfer ke " + recipient.display_name + ": " + description),
        db.prepare(`UPDATE characters SET money = money + ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND EXISTS (SELECT 1 FROM wallet_transactions WHERE id = ?)`)
          .bind(amount, targetId, senderLedgerId),
        db.prepare(`INSERT INTO wallet_transactions (id, character_id, transaction_type, amount, description)
          SELECT ?, ?, 'income', ?, ? WHERE EXISTS (SELECT 1 FROM wallet_transactions WHERE id = ?)`)
          .bind(receiverLedgerId, targetId, amount, "Transfer dari " + session.display_name + ": " + description, senderLedgerId)
      ]);
      if (!result[0]?.meta?.changes) return json({ error: "Saldo tidak cukup untuk transfer." }, 400);
      return json({ success: true, message: "Transfer berhasil ke " + recipient.display_name + ".", amount, recipient: recipient.display_name });
    }

    if (path === "/api/social/trade/item" && method === "POST") {
      const body = await readBody(request);
      const targetId = String(body?.targetCharacterId || "");
      const itemKey = String(body?.itemKey || "");
      const rawQuantity = Number(body?.quantity);
      if (!targetId || targetId === session.character_id) return json({ error: "Pilih pemain lain sebagai penerima." }, 400);
      if (!Number.isSafeInteger(rawQuantity) || rawQuantity < 1 || rawQuantity > 20) return json({ error: "Jumlah barang harus antara 1 dan 20." }, 400);
      if (!/^[a-z0-9_-]{1,60}$/.test(itemKey)) return json({ error: "Jenis barang tidak valid." }, 400);
      const recipient = await db.prepare("SELECT id, display_name FROM characters WHERE id = ?").bind(targetId).first();
      if (!recipient) return json({ error: "Pemain penerima tidak ditemukan." }, 404);
      await db.batch([
        db.prepare(`CREATE TABLE IF NOT EXISTS character_inventory (
          id TEXT PRIMARY KEY, character_id TEXT NOT NULL, item_key TEXT NOT NULL,
          item_name TEXT NOT NULL, quantity INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(character_id, item_key),
          FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
        )`),
        db.prepare(`CREATE TABLE IF NOT EXISTS player_item_transfers (
          id TEXT PRIMARY KEY, sender_character_id TEXT NOT NULL, recipient_character_id TEXT NOT NULL,
          item_key TEXT NOT NULL, item_name TEXT NOT NULL, quantity INTEGER NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(sender_character_id) REFERENCES characters(id) ON DELETE CASCADE,
          FOREIGN KEY(recipient_character_id) REFERENCES characters(id) ON DELETE CASCADE
        )`)
      ]);
      const owned = await db.prepare(`SELECT item_name, quantity FROM character_inventory
        WHERE character_id = ? AND item_key = ? AND quantity >= ?`)
        .bind(session.character_id, itemKey, rawQuantity).first();
      if (!owned) return json({ error: "Barang atau jumlahnya tidak tersedia di inventarismu." }, 400);
      const transferId = crypto.randomUUID();
      const result = await db.batch([
        db.prepare(`UPDATE character_inventory SET quantity = quantity - ?, updated_at = CURRENT_TIMESTAMP
          WHERE character_id = ? AND item_key = ? AND quantity >= ?`)
          .bind(rawQuantity, session.character_id, itemKey, rawQuantity),
        db.prepare(`INSERT INTO player_item_transfers (id, sender_character_id, recipient_character_id, item_key, item_name, quantity)
          SELECT ?, ?, ?, ?, ?, ? WHERE changes() > 0`)
          .bind(transferId, session.character_id, targetId, itemKey, owned.item_name, rawQuantity),
        db.prepare(`INSERT INTO character_inventory (id, character_id, item_key, item_name, quantity)
          SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM player_item_transfers WHERE id = ?)
          ON CONFLICT(character_id, item_key) DO UPDATE SET
          quantity = character_inventory.quantity + excluded.quantity, updated_at = CURRENT_TIMESTAMP`)
          .bind(crypto.randomUUID(), targetId, itemKey, owned.item_name, rawQuantity, transferId)
      ]);
      if (!result[0]?.meta?.changes) return json({ error: "Barang sudah berubah atau jumlahnya tidak cukup." }, 409);
      return json({ success: true, message: rawQuantity + " × " + owned.item_name + " berhasil dikirim ke " + recipient.display_name + "." });
    }

    return json({ error: "Endpoint sosial tidak ditemukan." }, 404);
  }

  return json({ error: "Endpoint API tidak ditemukan." }, 404);
}



// Durable Object: persistent WebSocket hub for player presence, movement and chat.
export class AurelithRealtime {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sockets = new Set();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/connect" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("WebSocket upgrade required", { status: 426 });
    }
    const characterId = request.headers.get("X-Aurelith-Character-Id");
    const displayName = request.headers.get("X-Aurelith-Display-Name") || "Warga";
    if (!characterId) return new Response("Unauthorized", { status: 401 });
    // Additive, idempotent setup for the realtime tables; never drops or resets existing data.
    await this.env.DB.batch([
      this.env.DB.prepare(`CREATE TABLE IF NOT EXISTS player_presence (
        character_id TEXT PRIMARY KEY, x REAL NOT NULL DEFAULT 600, y REAL NOT NULL DEFAULT 400,
        last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`),
      this.env.DB.prepare(`CREATE TABLE IF NOT EXISTS social_messages (
        id TEXT PRIMARY KEY, sender_character_id TEXT NOT NULL, recipient_character_id TEXT,
        channel TEXT NOT NULL CHECK(channel IN ('global','local','whisper')), message TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(recipient_character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`),
      this.env.DB.prepare(`CREATE TABLE IF NOT EXISTS player_friendships (
        id TEXT PRIMARY KEY, requester_character_id TEXT NOT NULL, addressee_character_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(requester_character_id, addressee_character_id),
        CHECK(requester_character_id <> addressee_character_id),
        FOREIGN KEY(requester_character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY(addressee_character_id) REFERENCES characters(id) ON DELETE CASCADE
      )`)
    ]);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.serializeAttachment({
      characterId,
      displayName,
      x: Number(request.headers.get("X-Aurelith-X")) || 600,
      y: Number(request.headers.get("X-Aurelith-Y")) || 400,
      connectedAt: Date.now()
    });
    this.state.acceptWebSocket(server);
    this.sockets.add(server);
    server.send(JSON.stringify({ type: "connected", characterId, serverTime: Date.now() }));
    await this.sendSnapshot(server);
    await this.persistPresence(server);
    await this.broadcast({
      type: "presence",
      action: "online",
      player: this.publicPlayer(server)
    }, server);
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": "aurelith-v1" }
    });
  }

  async webSocketMessage(socket, message) {
    let data;
    try {
      if (typeof message !== "string" || message.length > 6000) throw new Error("Pesan WebSocket tidak valid.");
      data = JSON.parse(message);
    } catch {
      socket.send(JSON.stringify({ type: "error", message: "Format pesan tidak valid." }));
      return;
    }
    const attachment = socket.deserializeAttachment();
    if (!attachment?.characterId) {
      socket.close(1008, "Sesi tidak valid");
      return;
    }
    try {
      if (data.type === "ping") {
        await this.persistPresence(socket);
        socket.send(JSON.stringify({ type: "pong", serverTime: Date.now() }));
        return;
      }
      if (data.type === "move") {
        const x = Number(data.x), y = Number(data.y);
        if (!Number.isFinite(x) || !Number.isFinite(y)) throw new Error("Koordinat tidak valid.");
        attachment.x = Math.max(25, Math.min(1175, x));
        attachment.y = Math.max(25, Math.min(775, y));
        socket.serializeAttachment(attachment);
        await this.env.DB.batch([
          this.env.DB.prepare("UPDATE characters SET x = ?, y = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
            .bind(attachment.x, attachment.y, attachment.characterId),
          this.env.DB.prepare(`INSERT INTO player_presence (character_id, x, y, last_seen)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(character_id) DO UPDATE SET x = excluded.x, y = excluded.y, last_seen = CURRENT_TIMESTAMP`)
            .bind(attachment.characterId, attachment.x, attachment.y)
        ]);
        await this.broadcast({ type: "position", player: this.publicPlayer(socket) });
        socket.send(JSON.stringify({ type: "move-ack", x: attachment.x, y: attachment.y }));
        return;
      }
      if (data.type === "chat") {
        await this.handleChat(socket, data);
        return;
      }
      if (data.type === "friend-request") {
        const targetId = String(data.targetCharacterId || "");
        if (!targetId || targetId === attachment.characterId) throw new Error("Pemain tujuan tidak valid.");
        const target = await this.env.DB.prepare("SELECT id FROM characters WHERE id = ?").bind(targetId).first();
        if (!target) throw new Error("Pemain tidak ditemukan.");
        const existing = await this.env.DB.prepare(`SELECT id, status FROM player_friendships
          WHERE (requester_character_id = ? AND addressee_character_id = ?)
             OR (requester_character_id = ? AND addressee_character_id = ?) LIMIT 1`)
          .bind(attachment.characterId,targetId,targetId,attachment.characterId).first();
        if (existing?.status === "accepted") throw new Error("Kalian sudah berteman.");
        if (existing?.status === "pending") {
          if (await this.env.DB.prepare("SELECT id FROM player_friendships WHERE id = ? AND addressee_character_id = ?").bind(existing.id,attachment.characterId).first()) {
            await this.env.DB.prepare("UPDATE player_friendships SET status = 'accepted', updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(existing.id).run();
            await this.broadcast({type:"friend-update",message:"Permintaan pertemanan diterima.",targetCharacterId:targetId,player:this.publicPlayer(socket)},null,targetId);
            socket.send(JSON.stringify({type:"friend-update",message:"Pertemanan otomatis diterima."}));
            return;
          }
          throw new Error("Permintaan pertemanan sudah dikirim.");
        }
        await this.env.DB.prepare(`INSERT INTO player_friendships
          (id, requester_character_id, addressee_character_id, status)
          VALUES (?, ?, ?, 'pending')`)
          .bind(crypto.randomUUID(),attachment.characterId,targetId).run();
        await this.broadcast({type:"friend-update",message:"Kamu menerima permintaan pertemanan baru.",targetCharacterId:targetId,fromCharacterId:attachment.characterId,fromName:attachment.displayName},null,targetId);
        socket.send(JSON.stringify({type:"friend-update",message:"Permintaan pertemanan terkirim."}));
        return;
      }
      if (data.type === "friend-response") {
        const requestId = String(data.requestId || "");
        const accept = data.accept === true;
        const request = await this.env.DB.prepare(`SELECT id, requester_character_id AS requesterId
          FROM player_friendships WHERE id = ? AND addressee_character_id = ? AND status = 'pending'`)
          .bind(requestId,attachment.characterId).first();
        if (!request) throw new Error("Permintaan tidak ditemukan atau sudah diproses.");
        await this.env.DB.prepare("UPDATE player_friendships SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
          .bind(accept ? "accepted" : "declined",requestId).run();
        await this.broadcast({type:"friend-update",message:accept ? "Permintaan pertemanan diterima." : "Permintaan pertemanan ditolak.",targetCharacterId:request.requesterId,fromCharacterId:attachment.characterId,fromName:attachment.displayName},null,request.requesterId);
        socket.send(JSON.stringify({type:"friend-update",message:accept ? "Pertemanan diterima." : "Permintaan ditolak."}));
        return;
      }
      if (data.type === "money-transfer") {
        const targetId = String(data.targetCharacterId || "");
        const amount = Number(data.amount);
        const description = String(data.description || "Transfer antarpemain").trim().slice(0,80) || "Transfer antarpemain";
        if (!targetId || targetId === attachment.characterId) throw new Error("Pilih pemain lain sebagai penerima.");
        if (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000) throw new Error("Nominal harus bilangan bulat antara 1 dan 100.000.");
        const recipient = await this.env.DB.prepare("SELECT id, display_name AS displayName FROM characters WHERE id = ?").bind(targetId).first();
        if (!recipient) throw new Error("Pemain penerima tidak ditemukan.");
        const senderLedgerId = crypto.randomUUID(), receiverLedgerId = crypto.randomUUID();
        const results = await this.env.DB.batch([
          this.env.DB.prepare("UPDATE characters SET money = money - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND money >= ?").bind(amount,attachment.characterId,amount),
          this.env.DB.prepare(`INSERT INTO wallet_transactions (id, character_id, transaction_type, amount, description)
            SELECT ?, ?, 'expense', ?, ? WHERE changes() > 0`).bind(senderLedgerId,attachment.characterId,amount,"Transfer ke "+recipient.displayName+": "+description),
          this.env.DB.prepare(`UPDATE characters SET money = money + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND EXISTS (SELECT 1 FROM wallet_transactions WHERE id = ?)`).bind(amount,targetId,senderLedgerId),
          this.env.DB.prepare(`INSERT INTO wallet_transactions (id, character_id, transaction_type, amount, description)
            SELECT ?, ?, 'income', ?, ? WHERE EXISTS (SELECT 1 FROM wallet_transactions WHERE id = ?)`).bind(receiverLedgerId,targetId,amount,"Transfer dari "+attachment.displayName+": "+description,senderLedgerId)
        ]);
        if (!results[0]?.meta?.changes) throw new Error("Saldo tidak cukup untuk transfer.");
        await this.broadcast({type:"money-received",targetCharacterId:targetId,fromName:attachment.displayName,amount},null,targetId);
        socket.send(JSON.stringify({type:"transaction-ack",action:"money-transfer",message:"Transfer berhasil ke "+recipient.displayName+".",amount}));
        return;
      }
      if (data.type === "item-transfer") {
        const targetId = String(data.targetCharacterId || "");
        const itemKey = String(data.itemKey || "");
        const quantity = Number(data.quantity);
        if (!targetId || targetId === attachment.characterId) throw new Error("Pilih pemain lain sebagai penerima.");
        if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 20) throw new Error("Jumlah barang harus antara 1 dan 20.");
        if (!/^[a-z0-9_-]{1,60}$/.test(itemKey)) throw new Error("Jenis barang tidak valid.");
        const recipient = await this.env.DB.prepare("SELECT id, display_name AS displayName FROM characters WHERE id = ?").bind(targetId).first();
        if (!recipient) throw new Error("Pemain penerima tidak ditemukan.");
        await this.env.DB.batch([
          this.env.DB.prepare(`CREATE TABLE IF NOT EXISTS character_inventory (
            id TEXT PRIMARY KEY, character_id TEXT NOT NULL, item_key TEXT NOT NULL,
            item_name TEXT NOT NULL, quantity INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(character_id,item_key),
            FOREIGN KEY(character_id) REFERENCES characters(id) ON DELETE CASCADE)`),
          this.env.DB.prepare(`CREATE TABLE IF NOT EXISTS player_item_transfers (
            id TEXT PRIMARY KEY, sender_character_id TEXT NOT NULL, recipient_character_id TEXT NOT NULL,
            item_key TEXT NOT NULL, item_name TEXT NOT NULL, quantity INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_character_id) REFERENCES characters(id) ON DELETE CASCADE,
            FOREIGN KEY(recipient_character_id) REFERENCES characters(id) ON DELETE CASCADE)`)
        ]);
        const owned = await this.env.DB.prepare("SELECT item_name FROM character_inventory WHERE character_id = ? AND item_key = ? AND quantity >= ?")
          .bind(attachment.characterId,itemKey,quantity).first();
        if (!owned) throw new Error("Barang atau jumlahnya tidak tersedia di inventarismu.");
        const transferId = crypto.randomUUID();
        const results = await this.env.DB.batch([
          this.env.DB.prepare("UPDATE character_inventory SET quantity = quantity - ?, updated_at = CURRENT_TIMESTAMP WHERE character_id = ? AND item_key = ? AND quantity >= ?").bind(quantity,attachment.characterId,itemKey,quantity),
          this.env.DB.prepare(`INSERT INTO player_item_transfers (id,sender_character_id,recipient_character_id,item_key,item_name,quantity)
            SELECT ?,?,?,?,?,? WHERE changes() > 0`).bind(transferId,attachment.characterId,targetId,itemKey,owned.item_name,quantity),
          this.env.DB.prepare(`INSERT INTO character_inventory (id,character_id,item_key,item_name,quantity)
            SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM player_item_transfers WHERE id = ?)
            ON CONFLICT(character_id,item_key) DO UPDATE SET quantity = character_inventory.quantity + excluded.quantity, updated_at = CURRENT_TIMESTAMP`).bind(crypto.randomUUID(),targetId,itemKey,owned.item_name,quantity,transferId)
        ]);
        if (!results[0]?.meta?.changes) throw new Error("Barang atau jumlahnya tidak cukup.");
        await this.broadcast({type:"item-received",targetCharacterId:targetId,fromName:attachment.displayName,itemName:owned.item_name,quantity},null,targetId);
        socket.send(JSON.stringify({type:"transaction-ack",action:"item-transfer",message:quantity+" × "+owned.item_name+" berhasil dikirim ke "+recipient.displayName+"."}));
        return;
      }
      if (data.type === "friend-event") {
        const targetId = String(data.targetCharacterId || "");
        if (!targetId || targetId === attachment.characterId) throw new Error("Pemain tujuan tidak valid.");
        const targetConnected = this.connectedSockets().some(s => s.deserializeAttachment()?.characterId === targetId);
        await this.broadcast({
          type: "social-notice",
          targetCharacterId: targetId,
          event: String(data.event || "activity").slice(0, 40),
          fromCharacterId: attachment.characterId,
          fromName: attachment.displayName
        }, null, targetId);
        socket.send(JSON.stringify({ type: "social-ack", targetCharacterId: targetId, deliveredLive: targetConnected }));
        return;
      }
      socket.send(JSON.stringify({ type: "error", message: "Jenis interaksi WebSocket tidak dikenal." }));
    } catch (error) {
      socket.send(JSON.stringify({ type: "error", message: String(error?.message || "Interaksi gagal.") }));
    }
  }

  async handleChat(socket, data) {
    const sender = socket.deserializeAttachment();
    const channel = String(data.channel || "global");
    const message = String(data.message || "").trim();
    const targetId = String(data.targetCharacterId || "");
    if (!["global", "local", "whisper"].includes(channel)) throw new Error("Channel chat tidak valid.");
    if (!message || message.length > 500 || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(message)) {
      throw new Error("Pesan harus 1–500 karakter yang valid.");
    }
    let recipient = null;
    if (channel === "whisper") {
      if (!targetId || targetId === sender.characterId) throw new Error("Pilih pemain lain untuk chat pribadi.");
      recipient = await this.env.DB.prepare("SELECT id, display_name AS displayName FROM characters WHERE id = ?")
        .bind(targetId).first();
      if (!recipient) throw new Error("Pemain tidak ditemukan.");
    }
    if (channel === "local") {
      const others = this.connectedSockets().map(s => s.deserializeAttachment()).filter(p => p?.characterId !== sender.characterId);
      const close = others.some(p => ((p.x - sender.x) ** 2 + (p.y - sender.y) ** 2) <= 62500);
      if (!close) throw new Error("Tidak ada pemain online di sekitar lokasi ini.");
    }
    const id = crypto.randomUUID();
    const row = await this.env.DB.prepare(`INSERT INTO social_messages
      (id, sender_character_id, recipient_character_id, channel, message)
      VALUES (?, ?, ?, ?, ?) RETURNING id, created_at AS createdAt`)
      .bind(id, sender.characterId, recipient?.id || null, channel, message).first();
    const packet = {
      type: "chat",
      message: {
        id, channel, message,
        senderCharacterId: sender.characterId,
        senderName: sender.displayName,
        recipientCharacterId: recipient?.id || null,
        recipientName: recipient?.displayName || null,
        createdAt: row?.createdAt || new Date().toISOString()
      }
    };
    if (channel === "whisper") {
      socket.send(JSON.stringify(packet));
      await this.broadcast(packet, socket, targetId);
    } else if (channel === "local") {
      const peers = this.connectedSockets().filter(s => {
        const p = s.deserializeAttachment();
        return p && ((p.x - sender.x) ** 2 + (p.y - sender.y) ** 2) <= 62500;
      });
      for (const peer of peers) this.safeSend(peer, packet);
    } else {
      await this.broadcast(packet);
    }
  }

  async sendSnapshot(socket) {
    const players = this.connectedSockets().map(s => this.publicPlayer(s))
      .filter(p => p.characterId !== socket.deserializeAttachment()?.characterId);
    this.safeSend(socket, { type: "snapshot", players });
  }

  async persistPresence(socket) {
    const p = socket.deserializeAttachment();
    if (!p?.characterId) return;
    await this.env.DB.prepare(`INSERT INTO player_presence (character_id, x, y, last_seen)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(character_id) DO UPDATE SET x = excluded.x, y = excluded.y, last_seen = CURRENT_TIMESTAMP`)
      .bind(p.characterId, p.x, p.y).run();
  }

  publicPlayer(socket) {
    const p = socket.deserializeAttachment() || {};
    return {
      characterId: p.characterId,
      displayName: p.displayName || "Warga",
      x: p.x ?? 600, y: p.y ?? 400,
      online: 1
    };
  }

  connectedSockets() {
    return this.state.getWebSockets();
  }

  safeSend(socket, packet) {
    try { socket.send(JSON.stringify(packet)); } catch {}
  }

  async broadcast(packet, exceptSocket = null, targetCharacterId = null) {
    for (const socket of this.connectedSockets()) {
      if (socket === exceptSocket) continue;
      const p = socket.deserializeAttachment();
      if (targetCharacterId && p?.characterId !== targetCharacterId) continue;
      this.safeSend(socket, packet);
    }
  }

  async webSocketClose(socket) {
    const p = socket.deserializeAttachment();
    this.sockets.delete(socket);
    try { socket.close(); } catch {}
    if (p?.characterId) {
      await this.broadcast({ type: "presence", action: "offline", player: {
        characterId: p.characterId, displayName: p.displayName
      }});
    }
  }

  async webSocketError(socket) {
    const p = socket.deserializeAttachment();
    this.sockets.delete(socket);
    if (p?.characterId) await this.broadcast({ type: "presence", action: "offline", player: {
      characterId: p.characterId, displayName: p.displayName
    }});
  }
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
