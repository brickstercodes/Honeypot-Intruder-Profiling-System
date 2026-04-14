import { useEffect, useMemo, useRef, useState } from "react";

type Marker = {
  id: string;
  label: string;
  lat?: number;
  lng?: number;
  severity: "low" | "medium" | "high" | "critical";
};

const tileSize = 256;

const SEV_COLOR: Record<Marker["severity"], string> = {
  low:      "#10b981",
  medium:   "#f59e0b",
  high:     "#f97316",
  critical: "#ef4444",
};

const clamp = (v: number, min: number, max: number) => Math.min(max, Math.max(min, v));

const project = (lat: number, lng: number, zoom: number) => {
  const sinLat = Math.sin((lat * Math.PI) / 180);
  const scale = tileSize * 2 ** zoom;
  return {
    x: ((lng + 180) / 360) * scale,
    y: (0.5 - Math.log((1 + clamp(sinLat, -0.9999, 0.9999)) / (1 - clamp(sinLat, -0.9999, 0.9999))) / (4 * Math.PI)) * scale,
  };
};

// Cluster markers within pixelRadius px of each other
function clusterMarkers(markers: (Marker & { px: number; py: number })[], pixelRadius = 28) {
  const clusters: { markers: typeof markers; px: number; py: number }[] = [];
  const used = new Set<number>();
  for (let i = 0; i < markers.length; i++) {
    if (used.has(i)) continue;
    const group = [markers[i]];
    used.add(i);
    for (let j = i + 1; j < markers.length; j++) {
      if (used.has(j)) continue;
      const dx = markers[i].px - markers[j].px;
      const dy = markers[i].py - markers[j].py;
      if (Math.sqrt(dx * dx + dy * dy) < pixelRadius) {
        group.push(markers[j]);
        used.add(j);
      }
    }
    const px = group.reduce((s, m) => s + m.px, 0) / group.length;
    const py = group.reduce((s, m) => s + m.py, 0) / group.length;
    clusters.push({ markers: group, px, py });
  }
  return clusters;
}

// Highest severity in cluster
function topSeverity(markers: Marker[]): Marker["severity"] {
  const rank = { low: 0, medium: 1, high: 2, critical: 3 };
  return markers.reduce((top, m) => rank[m.severity] > rank[top] ? m.severity : top, "low" as Marker["severity"]);
}

export default function WorldMap({ markers }: { markers: Marker[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 960, height: 400 });
  const [center, setCenter] = useState({ lat: 20, lng: 15 });
  const [zoom, setZoom] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(true); // toggle: all vs selected only

  useEffect(() => {
    if (!ref.current) return;
    const obs = new ResizeObserver(entries => {
      const e = entries[0];
      if (e) setSize({ width: e.contentRect.width, height: e.contentRect.height });
    });
    obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);

  const valid = useMemo(() =>
    markers.filter(m => typeof m.lat === "number" && typeof m.lng === "number"),
  [markers]);

  // Auto-center on markers
  useEffect(() => {
    if (valid.length === 0) return;
    const lat = valid.reduce((s, m) => s + (m.lat || 0), 0) / valid.length;
    const lng = valid.reduce((s, m) => s + (m.lng || 0), 0) / valid.length;
    setCenter({ lat, lng });
  }, [valid.length]);

  const centerWorld = project(center.lat, center.lng, zoom);
  const topLeft = { x: centerWorld.x - size.width / 2, y: centerWorld.y - size.height / 2 };
  const worldSize = tileSize * 2 ** zoom;

  const tiles = useMemo(() => {
    const sx = Math.floor(topLeft.x / tileSize);
    const ex = Math.floor((topLeft.x + size.width) / tileSize);
    const sy = Math.floor(topLeft.y / tileSize);
    const ey = Math.floor((topLeft.y + size.height) / tileSize);
    const res: { x: number; y: number; left: number; top: number }[] = [];
    for (let x = sx; x <= ex; x++) {
      for (let y = sy; y <= ey; y++) {
        const wx = ((x % 2 ** zoom) + 2 ** zoom) % 2 ** zoom;
        if (y < 0 || y >= 2 ** zoom) continue;
        res.push({ x: wx, y, left: x * tileSize - topLeft.x, top: y * tileSize - topLeft.y });
      }
    }
    return res;
  }, [size, topLeft.x, topLeft.y, zoom]);

  // Compute pixel positions
  const withPixels = useMemo(() => valid.map(m => {
    const pt = project(m.lat!, m.lng!, zoom);
    const rawLeft = pt.x - topLeft.x;
    const left = ((rawLeft % worldSize) + worldSize) % worldSize;
    const top = pt.y - topLeft.y;
    return { ...m, px: left, py: top };
  }).filter(m => m.py > -30 && m.py < size.height + 30), [valid, zoom, topLeft.x, topLeft.y, size.height, worldSize]);

  const clusters = useMemo(() => clusterMarkers(withPixels, 32), [withPixels]);

  // Which markers to show based on toggle/selection
  const visibleClusters = useMemo(() => {
    if (showAll || !selected) return clusters;
    return clusters.filter(c => c.markers.some(m => m.id === selected));
  }, [clusters, showAll, selected]);

  const selectedMarker = selected ? valid.find(m => m.id === selected) : null;

  return (
    <div className="space-y-3">
      {/* Controls */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="eyebrow">GeoIP attack map</div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Toggle: all / selected */}
          <div className="flex rounded-xl border border-white/8 bg-white/[0.02] p-0.5 text-xs">
            <button
              onClick={() => setShowAll(true)}
              className={`px-3 py-1 rounded-lg transition-all ${showAll ? "bg-sky-500/20 text-sky-300" : "text-slate-400 hover:text-slate-200"}`}
            >All ({valid.length})</button>
            <button
              onClick={() => setShowAll(false)}
              className={`px-3 py-1 rounded-lg transition-all ${!showAll ? "bg-sky-500/20 text-sky-300" : "text-slate-400 hover:text-slate-200"}`}
            >Selected</button>
          </div>
          {/* Zoom */}
          <div className="flex items-center gap-1 rounded-xl border border-white/8 bg-white/[0.02] p-0.5">
            <button onClick={() => setZoom(z => clamp(z - 1, 1, 5))} className="w-7 h-7 rounded-lg text-slate-300 hover:text-white hover:bg-white/8 transition-all text-sm">−</button>
            <span className="w-5 text-center text-xs text-slate-400">{zoom}</span>
            <button onClick={() => setZoom(z => clamp(z + 1, 1, 5))} className="w-7 h-7 rounded-lg text-slate-300 hover:text-white hover:bg-white/8 transition-all text-sm">+</button>
          </div>
          {selected && (
            <button onClick={() => { setSelected(null); setShowAll(true); }} className="text-xs text-slate-400 hover:text-slate-200 px-2">✕ clear</button>
          )}
        </div>
      </div>

      {/* Map */}
      <div ref={ref} className="relative overflow-hidden rounded-3xl border border-white/8" style={{ height: 400, background: "#0d1c30" }}>
        {/* Glow */}
        <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(circle at top, rgba(14,165,233,.12), transparent 50%)" }} />

        {/* Tiles */}
        <div className="absolute inset-0">
          {tiles.map(t => (
            <img
              key={`${zoom}-${t.x}-${t.y}`}
              alt=""
              className="absolute select-none"
              draggable={false}
              style={{ left: t.left, top: t.top, width: tileSize, height: tileSize, opacity: 0.55 }}
              src={`/api/osm-tile/${zoom}/${t.x}/${t.y}.png`}
            />
          ))}
        </div>

        {/* Clusters */}
        <div className="absolute inset-0">
          {visibleClusters.map((cluster, ci) => {
            const sev = topSeverity(cluster.markers);
            const color = SEV_COLOR[sev];
            const isMulti = cluster.markers.length > 1;
            const isSelected = cluster.markers.some(m => m.id === selected);

            return (
              <button
                key={ci}
                onClick={() => {
                  if (isMulti) {
                    // cycle through markers in cluster
                    const ids = cluster.markers.map(m => m.id);
                    const cur = ids.indexOf(selected || "");
                    setSelected(ids[(cur + 1) % ids.length]);
                    setShowAll(false);
                  } else {
                    const id = cluster.markers[0].id;
                    setSelected(selected === id ? null : id);
                    setShowAll(selected === id);
                  }
                }}
                className="absolute -translate-x-1/2 -translate-y-1/2 group"
                style={{ left: cluster.px, top: cluster.py }}
                title={cluster.markers.map(m => m.label).join("\n")}
              >
                {isMulti ? (
                  /* Cluster bubble */
                  <div
                    className="flex items-center justify-center rounded-full text-white font-bold transition-transform group-hover:scale-110"
                    style={{
                      width: 32, height: 32,
                      background: color,
                      boxShadow: `0 0 0 4px ${color}30, 0 0 16px ${color}60`,
                      fontSize: 11,
                      border: isSelected ? "2px solid white" : "2px solid transparent",
                    }}
                  >
                    {cluster.markers.length}
                  </div>
                ) : (
                  /* Single pin */
                  <div>
                    <div
                      className="transition-transform group-hover:scale-125"
                      style={{
                        width: isSelected ? 16 : 12,
                        height: isSelected ? 16 : 12,
                        borderRadius: "50%",
                        background: color,
                        border: `2px solid ${isSelected ? "white" : color}`,
                        boxShadow: `0 0 0 3px ${color}30, 0 0 ${isSelected ? 20 : 10}px ${color}`,
                      }}
                    />
                    {/* Pulse ring for critical */}
                    {sev === "critical" && (
                      <div
                        className="absolute inset-0 rounded-full animate-ping"
                        style={{ background: color, opacity: 0.3 }}
                      />
                    )}
                  </div>
                )}
              </button>
            );
          })}
        </div>

        {/* Selected marker tooltip */}
        {selectedMarker && (
          <div className="absolute bottom-3 left-3 right-3 sm:left-auto sm:right-3 sm:w-64 rounded-2xl border border-white/10 bg-black/70 backdrop-blur p-3 text-xs pointer-events-none">
            <div className="flex items-center gap-2 mb-1">
              <div className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[selectedMarker.severity] }} />
              <span className="font-mono text-white">{selectedMarker.id}</span>
              <span className={`ml-auto text-xs px-1.5 py-0.5 rounded-full`} style={{ background: SEV_COLOR[selectedMarker.severity] + "20", color: SEV_COLOR[selectedMarker.severity] }}>
                {selectedMarker.severity}
              </span>
            </div>
            <div className="text-slate-400">{selectedMarker.label}</div>
          </div>
        )}

        {/* Legend */}
        <div className="absolute top-3 left-3 flex gap-2 flex-wrap">
          {(["low","medium","high","critical"] as const).map(s => (
            <div key={s} className="flex items-center gap-1 rounded-full px-2 py-1 text-xs" style={{ background: "rgba(0,0,0,0.5)", backdropFilter: "blur(4px)" }}>
              <div className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
              <span className="text-slate-300 capitalize">{s}</span>
            </div>
          ))}
        </div>

        {valid.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-sm text-slate-500">
            No geo data yet — simulate or hit a decoy port
          </div>
        )}
      </div>

      {/* Marker list (clickable) */}
      {valid.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {valid.map(m => (
            <button
              key={m.id}
              onClick={() => {
                setSelected(selected === m.id ? null : m.id);
                setShowAll(selected === m.id);
              }}
              className="flex items-center gap-2 rounded-xl px-3 py-1.5 text-xs transition-all border"
              style={{
                borderColor: selected === m.id ? SEV_COLOR[m.severity] + "60" : "rgba(255,255,255,0.07)",
                background: selected === m.id ? SEV_COLOR[m.severity] + "15" : "rgba(255,255,255,0.02)",
                color: selected === m.id ? "white" : "#94a3b8",
              }}
            >
              <div className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[m.severity] }} />
              <span style={{ fontFamily: "var(--font-mono)" }}>{m.id}</span>
              <span className="text-slate-500">{m.label.split("·")[1]?.trim()}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
