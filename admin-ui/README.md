# Respire Admin UI

React consoles for administrators at `/admin` and users at `/dashboard`, built as a Vite single-file bundle. English is the default language, with Chinese available through the translation catalog. Memory search filters locally decrypted text; the browser does not decode or rank semantic vectors.

The web image serves the bundle independently of the API binary. JSON calls such as `/admin/me` and `/api/self` go to the API. Hash routes preserve browser navigation: `/admin#/users` and `/dashboard#/memories`. The `/admin/` prefix belongs to API routes.

| Command | Purpose |
|---|---|
| `npm ci` | Install the locked dependencies |
| `npm test` | Run existing routing and translation checks |
| `npm run build` | Produce `dist/index.html` and copy the embedded console artifact |
