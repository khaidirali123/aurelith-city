
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Pemeriksaan status backend
    if (url.pathname === "/api/health") {
      return Response.json({
        success: true,
        city: "Aurelith City",
        backend: "online",
        databaseBinding: Boolean(env.DB)
      });
    }

    // Memastikan database D1 bisa diakses
    if (url.pathname === "/api/db-test") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return Response.json({
          success: true,
          database: "connected",
          result
        });
      } catch (error) {
        return Response.json({
          success: false,
          database: "error",
          message: "Database belum dapat diakses."
        }, { status: 500 });
      }
    }

    // Tampilkan website untuk permintaan halaman lainnya
    return env.ASSETS.fetch(request);
  }
};
