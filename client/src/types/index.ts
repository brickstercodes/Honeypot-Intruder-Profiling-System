export interface IntrusionLog {
  id?: number;
  ip: string;
  userAgent?: string | null;
  browserFingerprint?: string | null;
  referrer?: string | null;
  timestamp?: Date | string | null;
  country?: string | null;
  city?: string | null;
  isp?: string | null;
  latitude?: string | null;
  longitude?: string | null;
  imageUrl?: string | null;
  imageKey?: string | null;
  deviceType?: string | null;
  osName?: string | null;
  browserName?: string | null;
  browserVersion?: string | null;
  threatLevel?: "low" | "medium" | "high" | "critical" | null;
  threatSummary?: string | null;
  defensiveActions?: string | null;
  reviewed?: number | null;
  notes?: string | null;
  createdAt?: Date | string | null;
  updatedAt?: Date | string | null;
}
