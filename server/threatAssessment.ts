/**
 * Gemini-powered threat assessment for intrusion events
 * Uses Google Gemini 2.0 Flash for high-speed, accurate analysis
 */

import type { IntrusionLog } from "../drizzle/schema";

export interface ThreatAssessment {
  threatLevel: "low" | "medium" | "high" | "critical";
  threatSummary: string;
  defensiveActions: string;
  attackType?: string;
  confidenceScore?: number;
  isTorExitNode?: boolean;
  isVpn?: boolean;
  isBot?: boolean;
  mitreTactics?: string[];
}

const GEMINI_API_URL =
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";

/**
 * Analyze intrusion data using Google Gemini AI
 */
export async function assessThreat(
  intrusion: Partial<IntrusionLog>
): Promise<ThreatAssessment> {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    console.warn("[ThreatAssessment] GEMINI_API_KEY not set, using fallback");
    return getFallbackAssessment(intrusion);
  }

  try {
    const prompt = buildThreatAssessmentPrompt(intrusion);

    const response = await fetch(`${GEMINI_API_URL}?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        systemInstruction: {
          parts: [{
            text: `You are an elite cybersecurity threat analyst specializing in intrusion detection and honeypot systems. 
Analyze intrusion data and provide structured JSON threat assessments. 
Be precise, use MITRE ATT&CK framework references where applicable.
Always respond with valid JSON only, no markdown, no explanation outside the JSON.`
          }],
        },
        generationConfig: {
          temperature: 0.2,
          topK: 40,
          topP: 0.8,
          responseMimeType: "application/json",
          responseSchema: {
            type: "OBJECT",
            properties: {
              threatLevel: { type: "STRING", enum: ["low", "medium", "high", "critical"] },
              threatSummary: { type: "STRING" },
              defensiveActions: { type: "STRING" },
              attackType: { type: "STRING" },
              confidenceScore: { type: "NUMBER" },
              isTorExitNode: { type: "BOOLEAN" },
              isVpn: { type: "BOOLEAN" },
              isBot: { type: "BOOLEAN" },
              mitreTactics: { type: "ARRAY", items: { type: "STRING" } },
            },
            required: ["threatLevel", "threatSummary", "defensiveActions", "attackType", "confidenceScore", "isBot", "mitreTactics"],
          },
        },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Gemini API error ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    const content = data?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!content) throw new Error("No response content from Gemini");

    const assessment = JSON.parse(content);
    return {
      threatLevel: assessment.threatLevel ?? "medium",
      threatSummary: assessment.threatSummary ?? "Assessment unavailable",
      defensiveActions: assessment.defensiveActions ?? "Manual review recommended",
      attackType: assessment.attackType,
      confidenceScore: assessment.confidenceScore,
      isTorExitNode: assessment.isTorExitNode ?? false,
      isVpn: assessment.isVpn ?? false,
      isBot: assessment.isBot ?? false,
      mitreTactics: assessment.mitreTactics ?? [],
    };
  } catch (error) {
    console.error("[ThreatAssessment] Gemini error:", error);
    return getFallbackAssessment(intrusion);
  }
}

function buildThreatAssessmentPrompt(intrusion: Partial<IntrusionLog>): string {
  return `Analyze this honeypot intrusion attempt and assess the threat level:

== INTRUSION DATA ==
IP Address: ${intrusion.ip || "Unknown"}
Timestamp: ${intrusion.timestamp?.toISOString() || new Date().toISOString()}
Country: ${intrusion.country || "Unknown"}
City: ${intrusion.city || "Unknown"}
ISP/Organization: ${intrusion.isp || "Unknown"}

== DEVICE PROFILE ==
Device Type: ${intrusion.deviceType || "Unknown"}
Operating System: ${intrusion.osName || "Unknown"}
Browser: ${intrusion.browserName || "Unknown"} ${intrusion.browserVersion || ""}
User Agent: ${intrusion.userAgent || "Unknown"}
Browser Fingerprint: ${intrusion.browserFingerprint || "None"}
Referrer: ${intrusion.referrer || "Direct / None"}

== CONTEXT ==
This is a honeypot system. The visitor accessed a trap URL.
No legitimate user should access this page. ANY access is inherently suspicious.

Assess using MITRE ATT&CK framework. Consider:
1. Reconnaissance patterns in the user agent
2. Geographic risk (sanctioned countries, known attack origins)  
3. ISP reputation (datacenter IPs = higher bot probability)
4. Browser fingerprint anomalies (headless browsers, automation tools)
5. Referrer source (no referrer = direct targeting)
6. Mobile vs Desktop attack patterns

Return threat level, detailed summary, defensive recommendations, attack classification, confidence score (0-1), and relevant MITRE ATT&CK tactics.`;
}

function getFallbackAssessment(intrusion: Partial<IntrusionLog>): ThreatAssessment {
  let threatLevel: ThreatAssessment["threatLevel"] = "medium";
  const indicators: string[] = [];

  const ua = (intrusion.userAgent || "").toLowerCase();
  if (ua.includes("bot") || ua.includes("crawler") || ua.includes("spider") ||
    ua.includes("scrapy") || ua.includes("python") || ua.includes("curl")) {
    threatLevel = "high";
    indicators.push("Automated tool detected in user agent");
  }

  if (!intrusion.referrer) {
    indicators.push("Direct access - no referrer (targeted attack indicator)");
  }

  return {
    threatLevel,
    threatSummary: `Honeypot access detected from ${intrusion.ip || "unknown IP"}. ${indicators.join(". ") || "Standard intrusion attempt."}`,
    defensiveActions: "Block IP at firewall level. Log for pattern analysis. Consider rate limiting from origin ASN.",
    attackType: ua.includes("bot") ? "Automated Scanning" : "Manual Reconnaissance",
    confidenceScore: 0.6,
    isTorExitNode: false,
    isVpn: false,
    isBot: ua.includes("bot") || ua.includes("python") || ua.includes("curl"),
    mitreTactics: ["TA0043 - Reconnaissance", "TA0009 - Collection"],
  };
}
