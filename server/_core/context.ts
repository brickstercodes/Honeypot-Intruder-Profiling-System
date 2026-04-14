import crypto from "node:crypto";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import { honeypotConfig } from "../honeypot/config";

export interface AdminUser {
  id: string;
  role: "admin";
  name: string;
}

export type TrpcContext = {
  req: CreateExpressContextOptions["req"];
  res: CreateExpressContextOptions["res"];
  user: AdminUser | null;
};

const hashValue = (value: string) =>
  crypto
    .createHash("sha256")
    .update(`${honeypotConfig.sessionCookieSecret}:${value}`)
    .digest("hex");

export const signAdminToken = (password: string) => hashValue(password);

export async function createContext(
  opts: CreateExpressContextOptions
): Promise<TrpcContext> {
  const token =
    opts.req.cookies?.[honeypotConfig.sessionCookieName] ||
    opts.req.headers?.["x-admin-token"];

  const expected = signAdminToken(honeypotConfig.adminPassword);
  const user =
    token === expected
      ? {
          id: "admin-console",
          role: "admin" as const,
          name: "Admin",
        }
      : null;

  return {
    req: opts.req,
    res: opts.res,
    user,
  };
}
