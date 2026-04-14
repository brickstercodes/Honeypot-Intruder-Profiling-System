import type { GeoProfile } from "@shared/honeypot";

const offlineLocations: Omit<GeoProfile, "source">[] = [
  {
    country: "United States",
    countryCode: "US",
    city: "Ashburn",
    region: "Virginia",
    asn: "AS14618",
    org: "Amazon.com, Inc.",
    latitude: 39.0438,
    longitude: -77.4874,
    timezone: "America/New_York",
  },
  {
    country: "Germany",
    countryCode: "DE",
    city: "Frankfurt",
    region: "Hesse",
    asn: "AS24940",
    org: "Hetzner Online GmbH",
    latitude: 50.1109,
    longitude: 8.6821,
    timezone: "Europe/Berlin",
  },
  {
    country: "Singapore",
    countryCode: "SG",
    city: "Singapore",
    region: "Singapore",
    asn: "AS16509",
    org: "Amazon Asia-Pacific",
    latitude: 1.3521,
    longitude: 103.8198,
    timezone: "Asia/Singapore",
  },
  {
    country: "Netherlands",
    countryCode: "NL",
    city: "Amsterdam",
    region: "North Holland",
    asn: "AS60781",
    org: "LeaseWeb Netherlands",
    latitude: 52.3676,
    longitude: 4.9041,
    timezone: "Europe/Amsterdam",
  },
  {
    country: "India",
    countryCode: "IN",
    city: "Mumbai",
    region: "Maharashtra",
    asn: "AS55836",
    org: "Reliance Jio",
    latitude: 19.076,
    longitude: 72.8777,
    timezone: "Asia/Kolkata",
  },
];

const localProfile: GeoProfile = {
  country: "Lab Network",
  countryCode: "LAB",
  city: "Localhost",
  region: "Private Segment",
  asn: "AS0",
  org: "Isolated Lab",
  source: "local",
};

const isPrivateIp = (ip: string) =>
  /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|localhost$)/i.test(ip);

const pickOfflineLocation = (ip: string): GeoProfile => {
  const seed = ip
    .split("")
    .reduce((sum, char) => sum + char.charCodeAt(0), 0);
  const base = offlineLocations[seed % offlineLocations.length];
  return { ...base, source: "offline" };
};

export async function lookupGeoProfile(
  ip: string,
  enabled = true
): Promise<GeoProfile> {
  if (!ip) return localProfile;
  // Demo mode: private/LAN IPs get deterministic offline geo so map pin shows
  if (isPrivateIp(ip)) return { ...pickOfflineLocation(ip), source: "offline" };

  if (!enabled) {
    return pickOfflineLocation(ip);
  }

  const fromIpWho = (data: any): GeoProfile | null => {
    if (!data?.success) return null;
    return {
      country: data.country || "Unknown",
      countryCode: data.country_code || "UN",
      city: data.city || "Unknown",
      region: data.region || "Unknown",
      asn: data.connection?.asn ? `AS${data.connection.asn}` : "AS?",
      org: data.connection?.org || data.connection?.isp || "Unknown",
      latitude: typeof data.latitude === "number" ? data.latitude : undefined,
      longitude: typeof data.longitude === "number" ? data.longitude : undefined,
      timezone: data.timezone?.id,
      source: "remote",
    };
  };

  const fromIpApiCo = (data: any): GeoProfile | null => {
    if (!data || data.error === true) return null;
    const asnRaw = String(data.asn || "");
    const asn = asnRaw.startsWith("AS") ? asnRaw : asnRaw ? `AS${asnRaw}` : "AS?";
    return {
      country: data.country_name || "Unknown",
      countryCode: data.country_code || "UN",
      city: data.city || "Unknown",
      region: data.region || "Unknown",
      asn,
      org: data.org || data.network || "Unknown",
      latitude: typeof data.latitude === "number" ? data.latitude : undefined,
      longitude: typeof data.longitude === "number" ? data.longitude : undefined,
      timezone: data.timezone,
      source: "remote",
    };
  };

  const fromIpInfo = (data: any): GeoProfile | null => {
    if (!data || data.bogon) return null;
    const [latRaw, lonRaw] = String(data.loc || ",").split(",");
    const lat = Number.parseFloat(latRaw);
    const lon = Number.parseFloat(lonRaw);
    return {
      country: data.country || "Unknown",
      countryCode: data.country || "UN",
      city: data.city || "Unknown",
      region: data.region || "Unknown",
      asn: data.asn?.asn || "AS?",
      org: data.org || data.asn?.name || "Unknown",
      latitude: Number.isFinite(lat) ? lat : undefined,
      longitude: Number.isFinite(lon) ? lon : undefined,
      timezone: data.timezone,
      source: "remote",
    };
  };

  try {
    const providers: Array<() => Promise<GeoProfile | null>> = [
      async () => {
        const response = await fetch(`https://ipwho.is/${ip}`);
        if (!response.ok) return null;
        return fromIpWho(await response.json());
      },
      async () => {
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        if (!response.ok) return null;
        return fromIpApiCo(await response.json());
      },
      async () => {
        const response = await fetch(`https://ipinfo.io/${ip}/json`);
        if (!response.ok) return null;
        return fromIpInfo(await response.json());
      },
    ];

    for (const load of providers) {
      try {
        const mapped = await load();
        if (mapped) return mapped;
      } catch {
        // Try next provider
      }
    }
  } catch (error) {
    console.warn("[GeoIP] lookup failed, using offline fallback", error);
  }

  return pickOfflineLocation(ip);
}