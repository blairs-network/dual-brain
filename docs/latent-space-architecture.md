# Latent Space: engineering blueprint

**The complete technical infrastructure for an AI-powered discovery engine where entities render themselves.** Latent Space takes a vibe query, sends it to Claude, and returns real-world entities — each manifesting through live data feeds, embedded players, 3D molecular viewers, real-time satellite trackers, generative audio, and interactive maps. This document covers every layer of the stack: from the React component that renders a spinning protein to the circuit breaker that catches a failing USGS endpoint. A senior full-stack engineer can start building from this tomorrow.

-----

## 1. The core stack and why each piece was chosen

The fundamental tension in Latent Space is that it’s a **heavily client-side interactive application** (WebGL, audio synthesis, real-time streams, complex animations) that also needs a **robust server-side proxy layer** (50+ API keys to hide, rate limiting, caching). The stack resolves this tension by pairing a lean frontend with serverless API proxying.

|Layer              |Choice                                          |Version        |Rationale                                                                                     |
|-------------------|------------------------------------------------|---------------|----------------------------------------------------------------------------------------------|
|**Build tool**     |Vite                                            |8.x            |Rolldown-powered (Rust bundler),  sub-second HMR, 10-30x faster production builds than Webpack|
|**UI framework**   |React                                           |19.x           |Ecosystem depth for 3D, audio, maps; concurrent features for streaming results                |
|**Router**         |TanStack Router                                 |latest         |Type-safe routing, search param management for shareable vibe queries                         |
|**Server state**   |TanStack Query                                  |5.x            |`useQueries()` handles 5-15 parallel calls natively; per-query loading/error states           |
|**Client state**   |Jotai                                           |2.x            |Atomic model — each entity card’s UI state (expanded, audio playing) is an independent atom   |
|**Animations**     |Motion 12.x + GSAP                              |latest         |Motion for declarative React transitions; GSAP for cinematic timeline sequences               |
|**Smooth scroll**  |Lenis                                           |1.3.x          |Momentum scrolling, syncs with both Motion and GSAP ScrollTrigger                             |
|**3D rendering**   |React Three Fiber                               |9.x + drei 10.x|Declarative Three.js in React; drei provides 100+ helpers                                     |
|**Maps**           |Mapbox GL JS v3 + react-map-gl                  |8.1.x          |50K free map loads/month, satellite imagery, Deck.gl integration for data overlays            |
|**Audio**          |Tone.js                                         |latest stable  |Full Web Audio synthesis, scheduling, effects chain                                           |
|**API proxy**      |Next.js API routes OR Hono on Cloudflare Workers|—              |Serverless functions hide API keys, handle CORS, apply rate limits                            |
|**Deploy (static)**|Vercel or Cloudflare Pages                      |—              |Vercel for Next.js native DX; Cloudflare for unlimited free bandwidth                         |
|**Database**       |Neon (serverless Postgres)                      |—              |Scale-to-zero, instant branching, native Vercel integration                                   |
|**ORM**            |Drizzle ORM                                     |~1.x           |5-7KB bundle, no codegen, edge-native, SQL-first                                              |
|**Auth**           |Clerk (MVP) → Better Auth (scale)               |—              |Clerk: 10K free MAU, 5-min setup; Better Auth: MIT-licensed, zero per-user cost               |
|**Cache**          |Upstash Redis                                   |—              |HTTP-based (no connection pool issues in serverless), 500K free commands/month                |
|**Monorepo**       |Turborepo                                       |2.x            |Native Vercel remote caching, minimal config                                                  |

**Why Vite over Next.js for the frontend?** Latent Space is not a content site — SEO is irrelevant for an interactive discovery tool behind a search input.  Vite gives maximum control over the rendering pipeline,  which is critical when mixing WebGL canvases, audio contexts, and real-time data streams. However, **if your team prefers co-located API routes**, Next.js App Router works — just mark most pages `'use client'` and accept the framework overhead.  The API proxy layer can live either in Next.js API routes or as standalone Cloudflare Workers.

**Why Jotai over Zustand?** When a single search returns 12 entities and each has independent loading state, render mode, audio state, and data feed status, Zustand’s centralized store causes unnecessary re-renders.  **Jotai’s atomic model**   means updating one entity’s audio state doesn’t trigger re-renders in the other 11 cards. The `jotai-tanstack-query` bridge  (v0.11.x) unifies server and client state elegantly via `atomWithQuery`.

-----

## 2. State management for streaming parallel results

A single Latent Space search triggers this sequence: user types a vibe → Claude returns structured entity data → **5-15 API calls fire simultaneously** to fetch live data for each entity → results stream into the UI as they resolve. The state architecture must handle progressive loading without blocking the entire UI on the slowest API.

**TanStack Query’s `useQueries()`** is the backbone. It accepts an array of query configs and returns an array of results, each with independent `isLoading`, `isError`, and `data` states:

```typescript
const entityQueries = useQueries({
  queries: entities.map(entity => ({
    queryKey: ['entity-data', entity.id, entity.type],
    queryFn: () => fetchEntityData(entity),
    staleTime: 5 * 60 * 1000,  // 5 min — entity data doesn't change fast
    retry: 2,
    retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 10000),
  })),
});
```

Each entity card reads its own query result independently. A molecule finishes loading and renders its 3D structure while the satellite tracker is still fetching TLE data — the UI never blocks. **Jotai atoms** track per-entity UI state  (is the audio playing? is the card expanded? which render mode?) without cross-entity re-render cascading. The `atomFamily` pattern creates atoms on demand:

```typescript
const entityUIAtom = atomFamily((id: string) => atom({
  expanded: false, renderMode: 'default', audioPlaying: false,
}));
```

For the Claude API call itself, use TanStack Query’s `useMutation` with streaming. Claude’s response includes the entity list, which triggers the parallel `useQueries` cascade. The **AbortController pattern** cancels all in-flight requests when the user types a new query, preventing stale results from appearing.

-----

## 3. Animation layer: Motion, GSAP, and Lenis working together

Three animation libraries serve distinct roles without conflicting. **Motion** (formerly Framer Motion, renamed mid-2025, now MIT-licensed)  handles all React-declarative animations: entity card reveals via `AnimatePresence`, layout reflows when the results grid changes, micro-interactions on hover/focus. Its `useScroll` hook drives scroll-linked effects. **GSAP**  (acquired by Webflow October 2024, made **100% free** May 2025 including formerly paid plugins like SplitText  and ScrollSmoother) handles complex timeline choreography  — cinematic entity reveal sequences where a card zooms in, text splits apart letter by letter, and a background gradient shifts in coordinated steps. **Lenis** (v1.3.x, MIT, by darkroom.engineering) provides the smooth-scroll foundation  that both libraries hook into.

The integration pattern connects Lenis’s scroll position to GSAP’s ScrollTrigger:

```typescript
lenis.on('scroll', ScrollTrigger.update);
gsap.ticker.add((time) => lenis.raf(time * 1000));
gsap.ticker.lagSmoothing(0);
```

**One licensing caveat on GSAP**: Webflow’s license prohibits use in tools competing with Webflow and allows Webflow to terminate the license at their discretion.  If Latent Space could ever be construed as a website builder competitor, Motion is the safer long-term bet.  For a discovery tool, this is unlikely to be an issue, but the risk is worth documenting.

-----

## 4. The renderer registry: how entities become themselves

The architectural heart of Latent Space is the **renderer system** — a plugin registry that maps entity types to React components, each loaded on demand. When Claude returns `{ type: "molecule", id: "ATP" }`, the registry resolves `MoleculeRenderer`, lazy-loads it, and renders a spinning 3D molecular structure. When it returns `{ type: "song", id: "spotify:track:..." }`, the `MusicRenderer` embeds a Spotify player.

**The registry is a Map from entity type strings to lazy-loaded React components:**

```typescript
const RENDERER_REGISTRY = new Map<string, React.LazyExoticComponent<any>>([
  ['molecule',   React.lazy(() => import('./renderers/MoleculeRenderer'))],
  ['song',       React.lazy(() => import('./renderers/MusicRenderer'))],
  ['place',      React.lazy(() => import('./renderers/MapRenderer'))],
  ['satellite',  React.lazy(() => import('./renderers/SatelliteRenderer'))],
  ['species',    React.lazy(() => import('./renderers/SpeciesRenderer'))],
  ['earthquake', React.lazy(() => import('./renderers/SeismicRenderer'))],
  ['artwork',    React.lazy(() => import('./renderers/ArtworkRenderer'))],
  ['star',       React.lazy(() => import('./renderers/SkyViewerRenderer'))],
  ['flight',     React.lazy(() => import('./renderers/FlightRenderer'))],
  ['ship',       React.lazy(() => import('./renderers/MaritimeRenderer'))],
  // ... 20+ more
]);
```

The `EntityRenderer` component wraps each lazy-loaded renderer in both a `Suspense` boundary (for loading) and an `ErrorBoundary` (for failures). This isolation means a crashing 3Dmol.js instance doesn’t take down the Spotify embed next to it:

```typescript
function EntityRenderer({ entity }) {
  const Component = RENDERER_REGISTRY.get(entity.type) ?? FallbackRenderer;
  return (
    <ErrorBoundary FallbackComponent={EntityError} onReset={() => refetchEntity(entity.id)}>
      <Suspense fallback={<RendererSkeleton type={entity.type} />}>
        <Component data={entity} />
      </Suspense>
    </ErrorBoundary>
  );
}
```

Each renderer is a self-contained package in the monorepo under `packages/renderers/`, with its own dependencies. `MoleculeRenderer` imports `3dmol`; `SatelliteRenderer` imports `satellite.js`; `MusicRenderer` constructs a Spotify iframe. **Vite’s code splitting** ensures users only download renderer code for entity types that appear in their results — the MoleculeRenderer’s ~20MB 3Dmol.js dependency never loads unless a molecule appears.

**iframe sandboxing** for third-party embeds (Spotify, YouTube, Twitter) uses strict `sandbox` attributes and CSP headers. The `sandbox="allow-scripts allow-same-origin"` combination is safe because the content is always cross-origin.  Embeds lazy-load via Intersection Observer — an iframe only initializes when it scrolls within 200px of the viewport,  critical when a search might return 15 entities with embedded players.

-----

## 5. Specific renderer implementations

### Spotify: oEmbed iframe, not the Web Playback SDK

As of May 2025, Spotify **restricted Web API access** to approved organizations only. Apps in development mode are capped at 25 test users.  The Web Playback SDK is effectively unavailable for new projects without a Spotify partnership.  **Use the oEmbed API instead** — it requires no authentication:

```
GET https://open.spotify.com/oembed?url=https://open.spotify.com/track/{id}
```

This returns an HTML iframe snippet, thumbnail URL, and title. The iframe embed supports a compact 80px height for inline players or 352px for full cards. For programmatic control (play/pause), Spotify’s **iFrame API** (`https://open.spotify.com/embed/iframe-api/v1`) provides `IFrameAPI.createController()` with `play()`, `pause()`, `seek()`, and playback update events.

### 3Dmol.js molecular viewer (v2.5.x)

Wrap 3Dmol.js imperatively with `useRef` + `useEffect`. The official npm package is `3dmol` (BSD-3-Clause, funded by NIH).  There is no maintained React wrapper — `molecule-3d-for-react` by Autodesk  targets React 15 and is abandoned.  The container div **must have explicit width and height** or the viewer crashes.  Load structures by PDB ID via `$3Dmol.download('pdb:1MO8', viewer, {}, callback)`  or from raw SDF/PDB data via `viewer.addModel(data, 'sdf')`. Render styles include cartoon (proteins), stick (small molecules), sphere (atoms), and surface overlays.

### Aladin Lite sky viewer (v3)

Aladin Lite v3 is a **Rust-to-WebAssembly** astronomical viewer maintained by CDS Strasbourg.  Install via `npm install aladin-lite`.  The initialization requires awaiting a WASM init promise before creating the viewer instance. Key API methods: `aladin.gotoRaDec(ra, dec)` to center on coordinates, `aladin.setFoV(degrees)` for zoom, `aladin.setBaseImageLayer(survey)` to switch between sky surveys (DSS2, 2MASS, allWISE).  The container div needs explicit dimensions. Available surveys include visible light (P/DSS2/color), infrared (P/2MASS/color), and radio wavelengths. The viewer is **GPLv3-licensed** — check compatibility with your distribution model.

### satellite.js for real-time orbital tracking (v5.x)

The `satellite.js` package (MIT, TypeScript rewrite in v5) implements SGP4/SDP4 orbital propagation.  Parse TLE data with `twoline2satrec()`, then call `propagate(satrec, new Date())` to get ECI position vectors.   Convert to geodetic coordinates (lat/lng/alt) via `eciToGeodetic()`. **SGP4 propagation is microseconds-per-satellite** — tracking 1,000 satellites at 1Hz is trivial in the browser. Fetch TLE data from CelesTrak (https://celestrak.org/, no login required, updated every few hours) or Space-Track (https://www.space-track.org/, free account required).  For visualization, **CesiumJS** (Apache 2.0, https://github.com/CesiumGS/cesium) provides a purpose-built WGS84 globe with time-dynamic simulation,   while a custom **React Three Fiber** globe gives more artistic control. The higher-level `tle.js` (v5.0.x) package provides convenience methods like `getLatLngObj(tle, timestamp)` and `getGroundTracks()`.

### Tone.js generative audio driven by data

Tone.js wraps the Web Audio API with musical abstractions.  **AudioContext must be started from a user gesture** — call `Tone.start()` inside a click handler.  Store all audio nodes in `useRef` (not state) to avoid re-renders, and dispose them in the useEffect cleanup. For data sonification, **map data dimensions to musical parameters**: values → pentatonic scale notes  (C4-E5 avoids dissonance), magnitude → velocity (0.3-1.0), density → tempo, category → timbre (sine for calm data, sawtooth for volatile). The `Reactronica` library (https://reactronica.com/) provides declarative React components (`<Song>`, `<Track>`, `<Instrument>`) that wrap Tone.js,  useful for prototyping audio-data mappings.

### Mapbox GL JS with satellite imagery and data overlays

Mapbox GL JS v3 offers **50,000 free map loads/month**.   Use `react-map-gl` (v8.1.x, maintained by vis.gl/OpenJS Foundation) for React bindings.  Enable satellite imagery via `mapStyle="mapbox://styles/mapbox/satellite-streets-v12"`. For data overlays (earthquake epicenters, weather patterns), use Mapbox’s source/layer system with GeoJSON data, or integrate **Deck.gl** via `@deck.gl/mapbox`‘s `MapboxOverlay` for GPU-accelerated rendering  of millions of data points. Deck.gl’s `ScatterplotLayer`, `HeatmapLayer`, and `HexagonLayer` handle large-scale geospatial visualization  that would overwhelm native Mapbox layers. Enable 3D terrain via `map.setTerrain({ source: 'mapbox-dem', exaggeration: 1.5 })`.

### WebSocket feeds: AISStream and Wikipedia EventStreams

**AISStream** (ship tracking): Connect to `wss://stream.aisstream.io/v0/stream` with a free API key. After connection, send a JSON subscription with bounding boxes and optional MMSI filters.  The feed delivers ~300 messages/second globally — **filter aggressively** by bounding box or specific vessels, or the connection will be dropped when the TCP queue backs up.

**Wikipedia EventStreams**: A Server-Sent Events (SSE) feed at `https://stream.wikimedia.org/v2/stream/recentchange`.  Use the browser’s native `EventSource` API — it handles auto-reconnection.  Supports historical replay via `?since=` parameter (31-day retention).  The public endpoint allows ~450 concurrent connections total across all consumers.

For WebSocket management in React, `react-use-websocket` provides `useWebSocket` and `useEventSource` hooks with built-in reconnection and the `share: true` option for singleton connections shared across components.  For raw WebSocket connections needing custom reconnection logic, use the `reconnecting-websocket` package (v4.4.0, stable/unmaintained)  or the actively maintained fork `@iam4x/reconnecting-websocket`.

### NOAA and USGS data feeds

**USGS earthquakes**: The real-time GeoJSON feeds at `https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/` provide auto-updated data (all_hour, all_day, all_week, all_month, plus magnitude-filtered variants like `4.5_day.geojson`). Standard GeoJSON FeatureCollection — parse directly with `response.json()` and feed into Mapbox or Deck.gl.  The FDSN query API at `/fdsnws/event/1/query` accepts parameters for time range, magnitude, and geographic bounds.

**NOAA weather**: The modern `api.weather.gov` API returns **GeoJSON**  (no API key required, but set a User-Agent header). The legacy Climate Data Online API at `ncei.noaa.gov/cdo-web/api/v2/` requires a free token and has a 5 req/s rate limit.  **Non-standard formats** from NOAA include GRIB2 (binary gridded weather model data), NetCDF (multidimensional scientific data), and DWML (proprietary XML, being deprecated). For the Latent Space use case, stick to the JSON/GeoJSON endpoints and avoid parsing binary scientific formats.

**USGS water services** are in a **major transition** — the legacy API at `waterservices.usgs.gov/nwis/` is being decommissioned by early 2027.  The replacement at `api.waterdata.usgs.gov/ogcapi/v0/` uses OGC API standards (GeoJSON-based).  Migrate to the new API now.

-----

## 6. API integration architecture: proxying, caching, and resilience

### The proxy gateway pattern

Every external API call routes through a serverless proxy that hides API keys, applies rate limits, checks the cache, and wraps the call in a circuit breaker. The unified flow:

```
Client → Edge Middleware (auth check, abuse detection)
       → Serverless Function /api/proxy/[provider]
       → Rate limiter (Bottleneck, per-provider)
       → Cache check (Upstash Redis)
       → Circuit breaker (opossum)
       → External API
       → Cache write → Response
```

A **dynamic proxy route** (`/api/proxy/[provider].ts`) uses a configuration map of all 50+ APIs — base URLs, auth types, rate limit parameters. This single route handler replaces 50 individual endpoint files. Each provider’s config specifies whether auth is via Bearer token, query parameter, or header, and the proxy injects the correct credential from environment variables at runtime.

### Rate limiting across heterogeneous APIs

Different APIs have wildly different rate limits: Wikipedia allows 200 req/s, USGS caps at 5 req/s, Spotify at roughly 30 req/s. **Bottleneck** (v2.19.5,  9.1M weekly npm downloads,  stable but unmaintained)  creates per-API limiters with individual `maxConcurrent` and `minTime` settings. Use a `Map<string, Bottleneck>` as a limiter registry, initializing each limiter from a config object. For distributed rate limiting across serverless function instances, **@upstash/ratelimit** provides Redis-backed sliding window algorithms that work in stateless environments.  Use Bottleneck in-process for immediate throttling and Upstash Ratelimit for global coordination.

**p-queue** (v9.1.x, by Sindre Sorhus) adds **priority ordering** — when a search returns 15 entities, core data (Wikipedia, Wikidata) gets priority 0 and fires first, enrichment data (Spotify, weather) gets priority 5, and supplementary data (NASA imagery, USGS) gets priority 10. The user sees the most important entities render first.

### Multi-tier caching with Upstash Redis

The caching architecture uses four tiers, each with different latency and scope:

- **Tier 1: In-memory LRU** (~0ms, per-function-instance). Use `lru-cache` for hot data. Evicted when the serverless function instance recycles.
- **Tier 2: Vercel CDN edge cache** (~5ms). Set `Cache-Control: s-maxage=60, stale-while-revalidate=300` on proxy responses. Serves stale data while revalidating in the background.
- **Tier 3: Upstash Redis** (~10-50ms, shared across all instances). HTTP-based REST API — no connection pool issues in serverless. Free tier: 500K commands/month,  256MB storage.
- **Tier 4: Origin API** (100-2000ms). The source of truth, called only on cache miss.

The **`cache-manager`** package (v7.2.x, 3.1M weekly downloads) provides a multi-store abstraction with Keyv-compatible adapters. Its `wrap()` method checks stores in order and writes back to all tiers on miss.

### Circuit breakers and graceful degradation

**opossum** (v8.1.x) wraps each API call in a circuit breaker. When an API’s failure rate exceeds 50% over 5 requests, the circuit opens and all subsequent calls immediately return the fallback — typically cached data or a “temporarily unavailable” placeholder. After 30 seconds, the circuit enters half-open state and allows one test request through. A `breakerRegistry` Map creates circuit breakers on demand, one per API.

On the React side, **react-error-boundary** wraps each `EntityRenderer` independently. A crashing 3Dmol.js viewer shows a “This data source is temporarily unavailable” card with a retry button, while the Spotify embed next to it continues playing.  Pair with **Sentry** (`@sentry/react`) for production error tracking with entity-type tags.

### Secrets management for 50+ API keys

**Infisical** (open-source,  MIT community edition,  https://github.com/Infisical/infisical) is the recommended secrets manager.  Self-hosted free tier supports unlimited secrets  with E2E encryption,   native Vercel integration, and a CLI that injects secrets as environment variables at runtime (`infisical run -- npm run dev`). It organizes keys by project and environment with folder hierarchy.  For smaller teams comfortable with Vercel’s built-in tooling, **Vercel’s environment variables UI** with `vercel pull --yes --environment=development` syncs all keys to a local `.env.local` file.

-----

## 7. Three.js and React Three Fiber: handling multiple 3D scenes

Three.js r183 (monthly releases, https://github.com/mrdoob/three.js) with **@react-three/fiber v9.5.x** and **@react-three/drei v10.7.x** powers all 3D rendering. The critical architectural challenge is that **browsers limit WebGL contexts to roughly 8-16** — if a search returns 12 entities and 4 are 3D, each with its own `<Canvas>`, you’ll hit the limit.

The solution is drei’s **`<View>` component**, which renders multiple virtual viewports within a single `<Canvas>`:

```tsx
<Canvas>
  <View track={moleculeRef}><MoleculeScene /></View>
  <View track={globeRef}><SatelliteScene /></View>
  <View track={particleRef}><ParticleScene /></View>
</Canvas>
```

Each `<View>` tracks a DOM element ref and clips its rendering to that element’s bounds. One WebGL context, unlimited scenes. Set **`frameloop="demand"`** for scenes that don’t need continuous animation — the scene only re-renders when state changes, saving GPU cycles for the scenes that do animate. Use `dpr={[1, 1.5]}` to cap pixel ratio on high-DPI displays, and `<instancedMesh>` for particle systems or data point clouds that might involve thousands of geometries.

Key ecosystem packages: `@react-three/postprocessing` for bloom/depth-of-field effects, `@react-three/gltfjsx` for converting GLTF models to JSX, and `@react-three/offscreen` for Web Worker rendering of computationally heavy scenes.

-----

## 8. Deployment, scaling, and what it costs

### Platform choice: Vercel vs Cloudflare

**Vercel** is the path of least resistance if using Next.js — native integration, preview deployments per PR,   Fluid Compute that doesn’t bill for I/O wait time  (critical for Claude API calls that wait 2-5 seconds). Pro plan at **$20/seat/month**  includes 1TB bandwidth, 10M edge requests,  and 12 concurrent builds.  The main downside is cost at scale — bandwidth overage at $0.15/GB adds up  for a media-rich app.

**Cloudflare Pages + Workers** is more cost-effective at scale: **unlimited free bandwidth** on Pages,   Workers execute in 300+ edge locations with near-zero cold starts,   and Durable Objects support WebSocket connections natively. The tradeoff is less polished DX for Next.js (requires `@cloudflare/next-on-pages` adapter) and Workers’ limited Node.js API surface.

**Practical recommendation**: Start with **Vercel Pro** for development velocity. If bandwidth costs exceed $500/month, evaluate migrating static assets to Cloudflare Pages with API proxy functions on Cloudflare Workers. The API proxy layer is portable — it’s just `fetch()` calls with added auth headers.

### Anthropic API costs dominate everything else

At current pricing, **Claude is 99%+ of infrastructure cost at scale**. Using **Claude Sonnet 4** ($3/MTok input, $15/MTok output)  with the assumed 500 input + 2,000 output tokens per search:

|Scale       |Daily Searches|Per-Search Cost|Monthly Cost |
|------------|--------------|---------------|-------------|
|**1K DAU**  |5,000         |$0.0315        |**~$4,700**  |
|**10K DAU** |50,000        |$0.0315        |**~$47,000** |
|**100K DAU**|500,000       |$0.0315        |**~$473,000**|

Switching to **Claude Haiku** ($1/$5 per MTok)  cuts costs **3x**  — $0.0105/search, or ~$1,575/month at 1K DAU and ~$158K/month at 100K DAU. The cost optimization strategy is **model routing**: use Haiku for entity classification and extraction (70% of queries), Sonnet for complex reasoning about abstract vibes (30% of queries). A 70/30 split at 100K DAU brings monthly API cost to roughly **$250K**.

**Prompt caching** saves 90% on cached input tokens   (5-minute or 1-hour TTL),   but since output tokens dominate cost (80%+ of total), the savings are modest — roughly 3-5% on total spend. **Batch API** offers 50% off all tokens but requires a 24-hour processing window   — unsuitable for real-time queries. The highest-leverage optimization is **aggressive response caching in Redis**: if a user searches “the feeling of rain” and another user searched the same yesterday, serve the cached Claude response. Entity data freshness matters; Claude’s classification of a vibe does not change hourly.

### Database and auth

**Neon** (serverless Postgres, acquired by Databricks in 2025)  integrates natively with Vercel — every PR gets an auto-provisioned database branch.  Usage-based pricing starts at $0.14/CU-hour compute and $0.35/GB-month storage,  with a free tier of 0.5 GB. Scale-to-zero means you pay nothing when idle. Use **Drizzle ORM** (~5-7KB, no codegen, 5.1M weekly npm downloads — it passed Prisma in late 2025)  for type-safe queries with minimal serverless cold-start overhead.

For auth, **Clerk** gets you to launch fastest: pre-built `<SignIn />` and `<UserButton />` components,  10K free MAUs, and 5-minute setup.   At scale (50K+ users), switch to **Better Auth** (MIT license, self-hosted, zero per-user cost).  The Auth.js team joined Better Auth in September 2025,  making it the spiritual successor to the most popular open-source auth library.  Clerk at 100K MAU would cost ~$1,800/month;  Better Auth costs only your server time.

-----

## 9. Monorepo structure and development workflow

### Turborepo workspace layout

```
latent-space/
├── apps/
│   └── web/                         # Vite + React (or Next.js) frontend
│       ├── src/
│       │   ├── routes/              # Page components
│       │   ├── components/          # Shared UI (search bar, layout, cards)
│       │   └── hooks/               # useVibeSearch, useEntityData
│       └── package.json
├── packages/
│   ├── renderers/                   # Entity renderer components
│   │   ├── src/
│   │   │   ├── MoleculeRenderer.tsx
│   │   │   ├── MusicRenderer.tsx
│   │   │   ├── SatelliteRenderer.tsx
│   │   │   ├── MapRenderer.tsx
│   │   │   ├── SkyViewerRenderer.tsx
│   │   │   ├── SeismicRenderer.tsx
│   │   │   ├── MaritimeRenderer.tsx
│   │   │   ├── FallbackRenderer.tsx
│   │   │   ├── registry.ts          # The Map<string, LazyComponent>
│   │   │   └── index.ts
│   │   └── package.json
│   ├── api-clients/                 # API integration clients
│   │   ├── src/
│   │   │   ├── anthropic.ts
│   │   │   ├── wikipedia.ts
│   │   │   ├── spotify.ts
│   │   │   ├── usgs.ts
│   │   │   ├── noaa.ts
│   │   │   ├── proxy.ts             # Unified proxy caller
│   │   │   └── config.ts            # API configs, rate limit params
│   │   └── package.json
│   ├── shared/                      # Types, utils, constants
│   │   ├── src/
│   │   │   ├── types/entity.ts      # Entity type definitions
│   │   │   ├── types/api.ts         # API response types
│   │   │   └── utils/
│   │   └── package.json
│   └── testing/                     # Shared MSW handlers, fixtures
│       ├── src/
│       │   ├── handlers/            # 50+ API mock handlers
│       │   └── fixtures/            # Sample response data
│       └── package.json
├── turbo.json
├── pnpm-workspace.yaml
├── docker-compose.yml               # Local Postgres + Redis
└── .env.example
```

**Turborepo** (v2.x) provides task orchestration with dependency-aware caching. The `turbo.json` config defines task relationships: `build` depends on upstream package builds (`^build`), `dev` runs persistently with no caching, `test` depends on builds. Remote caching via Vercel speeds CI by skipping unchanged packages.

### Testing pyramid for 50+ integrations

**MSW** (Mock Service Worker, v2.x) is the single source of truth for API mocks — the same handlers power local development, Storybook stories, Vitest unit tests, and Playwright E2E tests. Each API gets its own handler file in `packages/testing/src/handlers/`:

```typescript
// handlers/usgs.ts
import { http, HttpResponse } from 'msw';
export const usgsHandlers = [
  http.get('https://earthquake.usgs.gov/fdsnws/*', () =>
    HttpResponse.json(fixtures.usgs.recentEarthquakes)
  ),
];
```

All handlers aggregate into `allHandlers` and feed into `setupServer()` (Node) or `setupWorker()` (browser). **Vitest** (v4.x, 3x faster than Jest, ESM-native) runs unit and integration tests. **Storybook** (v8.x) with `msw-storybook-addon` (v2.0.7) provides visual testing per renderer — each entity type gets stories for loading, success, error, and edge-case states. **Playwright** handles E2E flows: type a vibe → verify entity cards appear → click an entity → verify renderer loads.

For **offline development**, set `NEXT_PUBLIC_USE_MOCKS=true` to activate MSW in the browser. The graceful degradation pattern in `api-clients/config.ts` checks for missing API keys in development and falls back to MSW mocks automatically — a developer can be productive without any API keys configured.

### CI/CD pipeline

GitHub Actions runs `pnpm turbo run lint type-check test` on every PR. Vercel auto-deploys preview environments with unique URLs. Environment variables are managed in three tiers:

- **Vercel Environment Variables UI**: Primary store for all 50+ API keys, separated by Production/Preview/Development
- **GitHub Secrets**: CI-only values (VERCEL_TOKEN, VERCEL_ORG_ID, deployment keys)
- **Local `.env.local`**: Synced via `vercel pull --yes --environment=development`

For teams, **Infisical** or **dotenv-vault** adds encrypted .env file syncing across developers without exposing keys in plaintext on any SaaS dashboard.

-----

## 10. Package reference table

Every major dependency at a glance, with verified versions and source URLs:

|Package                    |Version       |npm Weekly DL|Source                                           |
|---------------------------|--------------|-------------|-------------------------------------------------|
|`react`                    |19.x          |—            |https://github.com/facebook/react                |
|`vite`                     |8.x           |84M          |https://github.com/vitejs/vite                   |
|`@tanstack/react-query`    |5.90.x        |~5M          |https://github.com/TanStack/query                |
|`jotai`                    |2.4.x         |~2M          |https://github.com/pmndrs/jotai                  |
|`motion`                   |12.x          |30M+         |https://github.com/motiondivision/motion         |
|`gsap`                     |latest        |—            |https://gsap.com                                 |
|`lenis`                    |1.3.x         |—            |https://github.com/darkroomengineering/lenis     |
|`three`                    |0.183.x (r183)|—            |https://github.com/mrdoob/three.js               |
|`@react-three/fiber`       |9.5.x         |—            |https://github.com/pmndrs/react-three-fiber      |
|`@react-three/drei`        |10.7.x        |—            |https://github.com/pmndrs/drei                   |
|`tone`                     |latest stable |—            |https://github.com/Tonejs/Tone.js                |
|`mapbox-gl`                |3.x           |—            |https://www.mapbox.com/mapbox-gljs               |
|`react-map-gl`             |8.1.x         |—            |https://github.com/visgl/react-map-gl            |
|`satellite.js`             |5.x           |—            |https://github.com/shashwatak/satellite-js       |
|`3dmol`                    |2.5.x         |—            |https://github.com/3dmol/3Dmol.js                |
|`aladin-lite`              |3.x           |—            |https://github.com/cds-astro/aladin-lite         |
|`bottleneck`               |2.19.5        |9.1M         |https://github.com/SGrondin/bottleneck           |
|`p-queue`                  |9.1.x         |—            |https://github.com/sindresorhus/p-queue          |
|`opossum`                  |8.1.x         |—            |https://github.com/nodeshift/opossum             |
|`@upstash/redis`           |latest        |—            |https://github.com/upstash/upstash-redis         |
|`@upstash/ratelimit`       |latest        |—            |https://github.com/upstash/ratelimit             |
|`cache-manager`            |7.2.x         |3.1M         |https://github.com/jaredwray/cacheable           |
|`react-error-boundary`     |latest        |—            |https://github.com/bvaughn/react-error-boundary  |
|`react-use-websocket`      |latest        |—            |https://www.npmjs.com/package/react-use-websocket|
|`drizzle-orm`              |~1.x          |5.1M         |https://github.com/drizzle-team/drizzle-orm      |
|`msw`                      |2.x           |—            |https://github.com/mswjs/msw                     |
|`vitest`                   |4.x           |—            |https://github.com/vitest-dev/vitest             |
|`playwright`               |latest        |—            |https://github.com/microsoft/playwright          |
|`@supercharge/promise-pool`|3.x           |—            |https://github.com/supercharge/promise-pool      |
|`cesium`                   |1.138+        |—            |https://github.com/CesiumGS/cesium               |
|`tle.js`                   |5.0.x         |—            |https://github.com/davidcalhoun/tle.js           |
|`@deck.gl/mapbox`          |9.x           |—            |https://github.com/visgl/deck.gl                 |

-----

## Conclusion: what to build first

The highest-risk, highest-value pieces to validate early are the **renderer registry** and the **Claude prompt engineering** — everything else is standard web infrastructure. Build a vertical spike: one search query (“the feeling of standing in a cathedral”) → Claude returns 5 entities (a Gregorian chant on Spotify, the Cologne Cathedral on a map, a reverb-heavy generative audio patch, a Gothic rose window artwork, and the molecule of frankincense) → five renderers load and display simultaneously. If that spike works — parallel API calls resolving into lazy-loaded domain-specific renderers, each isolated by error boundaries — the architecture holds.

**Phase 1 (weeks 1-3)**: Vite + React scaffold, TanStack Query + Jotai state layer, Claude API proxy with prompt caching, renderer registry with 3 renderers (Map, Music, Fallback), Upstash Redis caching, deploy to Vercel. **Phase 2 (weeks 4-8)**: Add 10+ renderers (molecule, satellite, sky viewer, seismic, maritime, species, artwork, flight), WebSocket feeds, Tone.js audio layer, Lenis smooth scroll + Motion animations. **Phase 3 (weeks 9-12)**: Rate limiting + circuit breakers at scale, Storybook for all renderers, Playwright E2E suite, auth + saved paths in Neon, performance optimization (View component for shared WebGL context, Intersection Observer for lazy iframes).

The API cost curve is the only existential concern. At **$0.01-0.03 per search**, unit economics require either a paid tier, aggressive response caching (identical vibe queries served from Redis), or model routing that sends 70% of queries to the cheaper Haiku model. Every other infrastructure cost is a rounding error next to the Anthropic bill.
