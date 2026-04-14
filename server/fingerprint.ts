/**
 * Browser fingerprinting and device detection utilities
 * Extracts device and browser information from User-Agent
 */

export interface DeviceInfo {
  deviceType?: string; // mobile, tablet, desktop
  osName?: string;
  browserName?: string;
  browserVersion?: string;
}

/**
 * Parse User-Agent string to extract device and browser information
 */
export function parseUserAgent(userAgent: string): DeviceInfo {
  if (!userAgent) {
    return {};
  }

  const info: DeviceInfo = {};

  // Detect device type
  if (/mobile|android|iphone|ipod|blackberry|iemobile|opera mini/i.test(userAgent)) {
    info.deviceType = 'mobile';
  } else if (/tablet|ipad|playbook|silk|nexus 7|nexus 10|xoom|kindle/i.test(userAgent)) {
    info.deviceType = 'tablet';
  } else {
    info.deviceType = 'desktop';
  }

  // Detect OS (check mobile OS first before generic Linux)
  if (/iphone|ipad|ipod/i.test(userAgent)) {
    info.osName = 'iOS';
  } else if (/android/i.test(userAgent)) {
    info.osName = 'Android';
  } else if (/windows/i.test(userAgent)) {
    info.osName = 'Windows';
  } else if (/macintosh|mac os x/i.test(userAgent)) {
    info.osName = 'macOS';
  } else if (/linux/i.test(userAgent)) {
    info.osName = 'Linux';
  }

  // Detect browser
  if (/edg/i.test(userAgent)) {
    info.browserName = 'Edge';
    const match = userAgent.match(/edg[\/\\s]([\\d.]+)/);
    if (match) info.browserVersion = match[1].split('.')[0];
  } else if (/firefox/i.test(userAgent)) {
    info.browserName = 'Firefox';
    const match = userAgent.match(/firefox[\/\\s]([\\d.]+)/);
    if (match) info.browserVersion = match[1].split('.')[0];
  } else if (/chrome/i.test(userAgent) && !/chromium/i.test(userAgent) && !/edg/i.test(userAgent)) {
    info.browserName = 'Chrome';
    const match = userAgent.match(/chrome[\/\\s]([\\d.]+)/);
    if (match) info.browserVersion = match[1].split('.')[0];
  } else if (/safari/i.test(userAgent) && !/chrome/i.test(userAgent) && !/edg/i.test(userAgent)) {
    info.browserName = 'Safari';
    const match = userAgent.match(/version[\/\\s]([\\d.]+)/);
    if (match) info.browserVersion = match[1].split('.')[0];
  } else if (/opera|opr/i.test(userAgent)) {
    info.browserName = 'Opera';
    const match = userAgent.match(/(?:opera|opr)[\/\\s]([\\d.]+)/);
    if (match) info.browserVersion = match[1].split('.')[0];
  }

  return info;
}

/**
 * Generate a simple browser fingerprint from User-Agent and other headers
 * This is a basic implementation; a production system might use more sophisticated methods
 */
export function generateBrowserFingerprint(userAgent: string, acceptLanguage?: string, acceptEncoding?: string): string {
  const components = [
    userAgent,
    acceptLanguage || '',
    acceptEncoding || '',
  ];

  // Simple hash function (in production, use crypto.subtle.digest or similar)
  const combined = components.join('|');
  let hash = 0;
  for (let i = 0; i < combined.length; i++) {
    const char = combined.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16);
}
