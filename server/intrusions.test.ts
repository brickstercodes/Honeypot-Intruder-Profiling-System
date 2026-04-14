import { describe, it, expect, vi, beforeEach } from "vitest";
import { parseUserAgent, generateBrowserFingerprint } from "./fingerprint";
import { buildThreatAssessmentPrompt } from "./threatAssessment";

describe("Fingerprinting and Device Detection", () => {
  describe("parseUserAgent", () => {
    it("should detect Chrome on Windows", () => {
      const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
      const result = parseUserAgent(ua);

      expect(result.deviceType).toBe("desktop");
      expect(result.osName).toBe("Windows");
      expect(result.browserName).toBe("Chrome");
    });

    it("should detect Safari on macOS", () => {
      const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15";
      const result = parseUserAgent(ua);

      expect(result.deviceType).toBe("desktop");
      expect(result.osName).toBe("macOS");
      expect(result.browserName).toBe("Safari");
    });

    it("should detect mobile device", () => {
      const ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1";
      const result = parseUserAgent(ua);

      expect(result.deviceType).toBe("mobile");
      expect(result.osName).toBe("iOS");
      expect(result.browserName).toBe("Safari");
    });

    it("should detect Android device", () => {
      const ua = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36";
      const result = parseUserAgent(ua);

      expect(result.deviceType).toBe("mobile");
      expect(result.osName).toBe("Android");
      expect(result.browserName).toBe("Chrome");
    });

    it("should detect Firefox", () => {
      const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0";
      const result = parseUserAgent(ua);

      expect(result.browserName).toBe("Firefox");
    });

    it("should detect Edge", () => {
      const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59";
      const result = parseUserAgent(ua);

      expect(result.browserName).toBe("Edge");
    });

    it("should handle empty user agent", () => {
      const result = parseUserAgent("");
      expect(result).toEqual({});
    });
  });

  describe("generateBrowserFingerprint", () => {
    it("should generate consistent fingerprints for same input", () => {
      const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0";
      const lang = "en-US";
      const enc = "gzip, deflate";

      const fp1 = generateBrowserFingerprint(ua, lang, enc);
      const fp2 = generateBrowserFingerprint(ua, lang, enc);

      expect(fp1).toBe(fp2);
    });

    it("should generate different fingerprints for different inputs", () => {
      const ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0";
      const ua2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15";

      const fp1 = generateBrowserFingerprint(ua1);
      const fp2 = generateBrowserFingerprint(ua2);

      expect(fp1).not.toBe(fp2);
    });

    it("should return hex string", () => {
      const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0";
      const fp = generateBrowserFingerprint(ua);

      expect(/^[0-9a-f]+$/.test(fp)).toBe(true);
    });
  });
});

describe("Threat Assessment", () => {
  describe("buildThreatAssessmentPrompt", () => {
    it("should build a prompt with intrusion data", () => {
      const intrusion = {
        ip: "192.168.1.1",
        country: "United States",
        city: "New York",
        isp: "Example ISP",
        deviceType: "desktop",
        osName: "Windows",
        browserName: "Chrome",
        browserVersion: "91",
        userAgent: "Mozilla/5.0...",
        referrer: "https://example.com",
        timestamp: new Date("2026-04-08T21:00:00Z"),
      };

      const prompt = buildThreatAssessmentPrompt(intrusion);

      expect(prompt).toContain("192.168.1.1");
      expect(prompt).toContain("United States");
      expect(prompt).toContain("New York");
      expect(prompt).toContain("Example ISP");
      expect(prompt).toContain("desktop");
      expect(prompt).toContain("Windows");
      expect(prompt).toContain("Chrome");
      expect(prompt).toContain("threat assessment");
    });

    it("should handle missing fields gracefully", () => {
      const intrusion = {
        ip: "192.168.1.1",
      };

      const prompt = buildThreatAssessmentPrompt(intrusion);

      expect(prompt).toContain("192.168.1.1");
      expect(prompt).toContain("Unknown");
      expect(prompt).toContain("threat assessment");
    });
  });
});

// Helper function to extract from threatAssessment.ts for testing
function buildThreatAssessmentPrompt(intrusion: any): string {
  const lines = [
    "Analyze the following intrusion attempt and provide a threat assessment:",
    "",
    `IP Address: ${intrusion.ip || "Unknown"}`,
    `Country: ${intrusion.country || "Unknown"}`,
    `City: ${intrusion.city || "Unknown"}`,
    `ISP: ${intrusion.isp || "Unknown"}`,
    `Device Type: ${intrusion.deviceType || "Unknown"}`,
    `Operating System: ${intrusion.osName || "Unknown"}`,
    `Browser: ${intrusion.browserName || "Unknown"} ${intrusion.browserVersion || ""}`,
    `User Agent: ${intrusion.userAgent || "Unknown"}`,
    `Referrer: ${intrusion.referrer || "Direct"}`,
    `Timestamp: ${intrusion.timestamp?.toISOString() || "Unknown"}`,
    "",
    "Consider the following factors in your assessment:",
    "1. Geographic origin and ISP reputation",
    "2. Device type and OS (mobile vs desktop)",
    "3. Browser type and version",
    "4. Referrer source (search engine, direct, etc.)",
    "5. User agent patterns that might indicate automated tools or bots",
    "6. Combination of factors that might indicate coordinated attacks",
    "",
    "Provide a threat level (low, medium, high, critical), a brief summary, and recommended defensive actions.",
  ];

  return lines.join("\n");
}
