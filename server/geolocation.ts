/**
 * Enhanced geolocation service with richer data
 */

export interface GeolocationData {
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  isp?: string;
  org?: string;
  asn?: string;
  latitude?: string;
  longitude?: string;
  timezone?: string;
  isProxy?: boolean;
  isDatacenter?: boolean;
}

export async function lookupGeolocation(ip: string): Promise<GeolocationData> {
  // Skip private/local IPs
  if (isPrivateIP(ip)) {
    return { country: "Local Network", city: "localhost" };
  }

  const fromIpApi = (data: any): GeolocationData | null => {
    if (!data || data.status !== "success") return null;
    return {
      country: data.country || undefined,
      countryCode: data.countryCode || undefined,
      region: data.regionName || undefined,
      city: data.city || undefined,
      isp: data.isp || undefined,
      org: data.org || undefined,
      asn: data.as || undefined,
      latitude: typeof data.lat === "number" ? String(data.lat) : undefined,
      longitude: typeof data.lon === "number" ? String(data.lon) : undefined,
      timezone: data.timezone || undefined,
      isProxy: data.proxy === true,
      isDatacenter: data.hosting === true,
    };
  };

  const fromIpWho = (data: any): GeolocationData | null => {
    if (!data?.success) return null;
    return {
      country: data.country || undefined,
      countryCode: data.country_code || undefined,
      region: data.region || undefined,
      city: data.city || undefined,
      isp: data.connection?.isp,
      org: data.connection?.org,
      asn: data.connection?.asn ? `AS${data.connection.asn}` : undefined,
      latitude: data.latitude ? String(data.latitude) : undefined,
      longitude: data.longitude ? String(data.longitude) : undefined,
      timezone: data.timezone?.id,
      isProxy: data.security?.vpn === true || data.security?.proxy === true || data.security?.tor === true,
      isDatacenter: data.connection?.org ? /hosting|data center|cloud|aws|google|azure|digitalocean|linode|hetzner|ovh/i.test(String(data.connection.org)) : undefined,
    };
  };

  const fromIpApiCo = (data: any): GeolocationData | null => {
    if (!data || data.error) return null;
    return {
      country: data.country_name || undefined,
      countryCode: data.country_code || undefined,
      region: data.region || undefined,
      city: data.city || undefined,
      isp: data.org || undefined,
      org: data.org || undefined,
      asn: data.asn || undefined,
      latitude: typeof data.latitude === "number" ? String(data.latitude) : undefined,
      longitude: typeof data.longitude === "number" ? String(data.longitude) : undefined,
      timezone: data.timezone || undefined,
      isProxy: data.security?.is_proxy === true,
      isDatacenter: data.org ? /cloud|hosting|data center|aws|google|azure|digitalocean|linode|hetzner|ovh/i.test(String(data.org)) : undefined,
    };
  };

  try {
    const providers: Array<() => Promise<GeolocationData | null>> = [
      async () => {
        const response = await fetch(
          `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,timezone,proxy,hosting`
        );
        if (!response.ok) return null;
        return fromIpApi(await response.json());
      },
      async () => {
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        if (!response.ok) return null;
        return fromIpApiCo(await response.json());
      },
      async () => {
        const response = await fetch(`https://ipwho.is/${ip}`);
        if (!response.ok) return null;
        return fromIpWho(await response.json());
      },
    ];

    for (const load of providers) {
      try {
        const result = await load();
        if (result) return result;
      } catch (error) {
        console.error(`[Geolocation] Provider failed for ${ip}:`, error);
      }
    }
    return {};
  } catch (error) {
    console.error(`[Geolocation] Error for ${ip}:`, error);
    return {};
  }
}

function isPrivateIP(ip: string): boolean {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^::1$/,
    /^localhost$/i,
  ];
  return privateRanges.some((r) => r.test(ip));
}
