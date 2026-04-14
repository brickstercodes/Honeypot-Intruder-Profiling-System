import { eq, desc, count, isNotNull, and, gte, lte, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { InsertUser, users, intrusion_logs, InsertIntrusionLog } from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export async function createIntrusionLog(log: InsertIntrusionLog) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot create intrusion log: database not available");
    return undefined;
  }

  try {
    const result = await db.insert(intrusion_logs).values(log);
    return result;
  } catch (error) {
    console.error("[Database] Failed to create intrusion log:", error);
    throw error;
  }
}

export async function getIntrusionLogs(limit = 100, offset = 0) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get intrusion logs: database not available");
    return [];
  }

  try {
    const result = await db.select().from(intrusion_logs).orderBy(desc(intrusion_logs.timestamp)).limit(limit).offset(offset);
    return result;
  } catch (error) {
    console.error("[Database] Failed to get intrusion logs:", error);
    throw error;
  }
}

export async function getIntrusionLogById(id: number) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get intrusion log: database not available");
    return undefined;
  }

  try {
    const result = await db.select().from(intrusion_logs).where(eq(intrusion_logs.id, id)).limit(1);
    return result.length > 0 ? result[0] : undefined;
  } catch (error) {
    console.error("[Database] Failed to get intrusion log:", error);
    throw error;
  }
}

export async function updateIntrusionLog(id: number, updates: Partial<InsertIntrusionLog>) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot update intrusion log: database not available");
    return undefined;
  }

  try {
    const result = await db.update(intrusion_logs).set(updates).where(eq(intrusion_logs.id, id));
    return result;
  } catch (error) {
    console.error("[Database] Failed to update intrusion log:", error);
    throw error;
  }
}

export async function getIntrusionLogCount() {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get intrusion log count: database not available");
    return 0;
  }

  try {
    const result = await db.select({ count: count() }).from(intrusion_logs);
    return result[0]?.count ?? 0;
  } catch (error) {
    console.error("[Database] Failed to get intrusion log count:", error);
    throw error;
  }
}

export async function getTopAttackingIPs(limit = 10) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get top attacking IPs: database not available");
    return [];
  }

  try {
    const result = await db.select({
      ip: intrusion_logs.ip,
      count: count(),
    }).from(intrusion_logs).groupBy(intrusion_logs.ip).orderBy(desc(count())).limit(limit);
    return result;
  } catch (error) {
    console.error("[Database] Failed to get top attacking IPs:", error);
    throw error;
  }
}

export async function getTopCountries(limit = 10) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get top countries: database not available");
    return [];
  }

  try {
    const result = await db.select({
      country: intrusion_logs.country,
      count: count(),
    }).from(intrusion_logs).where(isNotNull(intrusion_logs.country)).groupBy(intrusion_logs.country).orderBy(desc(count())).limit(limit);
    return result;
  } catch (error) {
    console.error("[Database] Failed to get top countries:", error);
    throw error;
  }
}

export async function getIntrusionsByDateRange(startDate: Date, endDate: Date) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get intrusions by date range: database not available");
    return [];
  }

  try {
    const result = await db.select().from(intrusion_logs).where(
      and(
        gte(intrusion_logs.timestamp, startDate),
        lte(intrusion_logs.timestamp, endDate)
      )
    ).orderBy(desc(intrusion_logs.timestamp));
    return result;
  } catch (error) {
    console.error("[Database] Failed to get intrusions by date range:", error);
    throw error;
  }
}

// TODO: add more feature queries here as your schema grows.


export async function getIntrusionTimeline(days = 7) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get intrusion timeline: database not available");
    return [];
  }
  try {
    // Get intrusions from the last N days
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    
    const result = await db.select().from(intrusion_logs)
      .where(gte(intrusion_logs.timestamp, startDate))
      .orderBy(intrusion_logs.timestamp);
    
    // Aggregate by date
    const timelineMap = new Map<string, number>();
    
    result.forEach((log) => {
      if (log.timestamp) {
        const date = new Date(log.timestamp).toISOString().split('T')[0];
        timelineMap.set(date, (timelineMap.get(date) || 0) + 1);
      }
    });
    
    // Convert to array and fill in missing dates
    const timeline = [];
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      timeline.push({
        date: dateStr,
        count: timelineMap.get(dateStr) || 0,
      });
    }
    
    return timeline;
  } catch (error) {
    console.error("[Database] Failed to get intrusion timeline:", error);
    throw error;
  }
}

export async function getThreatLevelDistribution() {
  const db = await getDb();
  if (!db) return { low: 0, medium: 0, high: 0, critical: 0 };
  try {
    const result = await db
      .select({ threatLevel: intrusion_logs.threatLevel, count: count() })
      .from(intrusion_logs)
      .groupBy(intrusion_logs.threatLevel);
    const dist: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    result.forEach((r: any) => { if (r.threatLevel) dist[r.threatLevel] = Number(r.count); });
    return dist;
  } catch (error) {
    console.error("[Database] Failed to get threat distribution:", error);
    return { low: 0, medium: 0, high: 0, critical: 0 };
  }
}

export async function getBlockedIPs() {
  const db = await getDb();
  if (!db) return [];
  try {
    const { blocked_ips } = await import("../drizzle/schema");
    return await db.select().from(blocked_ips).orderBy(desc(blocked_ips.blockedAt));
  } catch (error) {
    console.error("[Database] Failed to get blocked IPs:", error);
    return [];
  }
}

export async function blockIP(ip: string, reason?: string, intrusionId?: number) {
  const db = await getDb();
  if (!db) return;
  try {
    const { blocked_ips } = await import("../drizzle/schema");
    await db.insert(blocked_ips).values({ ip, reason, intrusionId }).onDuplicateKeyUpdate({ set: { reason } });
    if (intrusionId) await db.update(intrusion_logs).set({ blocked: 1 }).where(eq(intrusion_logs.id, intrusionId));
  } catch (error) {
    console.error("[Database] Failed to block IP:", error);
  }
}

export async function unblockIP(ip: string) {
  const db = await getDb();
  if (!db) return;
  try {
    const { blocked_ips } = await import("../drizzle/schema");
    await db.delete(blocked_ips).where(eq(blocked_ips.ip, ip));
  } catch (error) {
    console.error("[Database] Failed to unblock IP:", error);
  }
}

export async function getFlaggedIntrusions() {
  const db = await getDb();
  if (!db) return [];
  try {
    return await db.select().from(intrusion_logs)
      .where(eq(intrusion_logs.flagged, 1))
      .orderBy(desc(intrusion_logs.timestamp))
      .limit(100);
  } catch (error) {
    console.error("[Database] Failed to get flagged intrusions:", error);
    return [];
  }
}

export async function getRecentIntrusions(limit = 5) {
  const db = await getDb();
  if (!db) return [];
  try {
    return await db.select().from(intrusion_logs)
      .orderBy(desc(intrusion_logs.timestamp))
      .limit(limit);
  } catch (error) {
    console.error("[Database] Failed to get recent intrusions:", error);
    return [];
  }
}
