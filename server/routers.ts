import fs from "node:fs";
import { z } from "zod";
import { honeypotConfig } from "./honeypot/config";
import { honeypotEngine } from "./honeypot/engine";
import { decryptEvidenceLine, getForensicPaths } from "./honeypot/storage";
import { adminProcedure, publicProcedure, router } from "./_core/trpc";

export const appRouter = router({
  auth: router({
    me: publicProcedure.query(({ ctx }) => ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      ctx.res.clearCookie(honeypotConfig.sessionCookieName, {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
      });
      return { success: true } as const;
    }),
  }),

  dashboard: router({
    snapshot: adminProcedure.query(() => honeypotEngine.getSnapshot()),

    session: adminProcedure
      .input(z.object({ sessionId: z.string() }))
      .query(({ input }) => honeypotEngine.getSession(input.sessionId)),

    blockIp: adminProcedure
      .input(z.object({ ip: z.string(), reason: z.string().optional() }))
      .mutation(({ input }) => {
        honeypotEngine.blockIp(input.ip, input.reason);
        return { success: true } as const;
      }),

    unblockIp: adminProcedure
      .input(z.object({ ip: z.string() }))
      .mutation(({ input }) => {
        honeypotEngine.unblockIp(input.ip);
        return { success: true } as const;
      }),

    terminateSession: adminProcedure
      .input(z.object({ sessionId: z.string() }))
      .mutation(({ input }) => {
        honeypotEngine.terminateSession(input.sessionId);
        return { success: true } as const;
      }),

    simulate: adminProcedure
      .input(z.object({ count: z.number().min(1).max(100).default(12) }))
      .mutation(async ({ input }) => {
        await honeypotEngine.simulateAttackBatch(input.count);
        return { success: true } as const;
      }),

    forensicChain: adminProcedure
      .input(z.object({ limit: z.number().min(1).max(200).default(50) }).optional())
      .query(({ input }) => {
        const { evidenceLogPath } = getForensicPaths();
        if (!fs.existsSync(evidenceLogPath)) {
          return { entries: [], totalCount: 0, chainValid: true };
        }

        const raw = fs.readFileSync(evidenceLogPath, "utf8");
        const lines = raw.trim().split("\n").filter(Boolean);
        const limit = input?.limit ?? 50;

        // Decrypt and parse entries (most recent first)
        const entries: Array<{
          kind: string;
          timestamp: string;
          hash: string;
          prevHash: string;
          payload: unknown;
          chainOk: boolean;
        }> = [];

        let prevHash: string | null = null;
        let chainValid = true;

        for (const line of lines) {
          try {
            const enc = JSON.parse(line) as {
              version: number;
              alg: string;
              iv: string;
              tag: string;
              ciphertext: string;
              hash: string;
            };
            const decrypted = decryptEvidenceLine(enc);
            const envelope = JSON.parse(decrypted) as {
              kind: string;
              timestamp: string;
              hash: string;
              prevHash: string;
              payload: unknown;
            };

            // Verify chain link: this entry's prevHash must match the previous entry's hash
            const chainOk = prevHash === null || envelope.prevHash === prevHash;
            if (!chainOk) chainValid = false;

            entries.push({
              kind: envelope.kind,
              timestamp: envelope.timestamp,
              hash: enc.hash,
              prevHash: envelope.prevHash,
              payload: envelope.payload,
              chainOk,
            });

            prevHash = enc.hash;
          } catch {
            // Corrupted entry — mark chain as broken
            chainValid = false;
          }
        }

        return {
          entries: entries.slice(-limit).reverse(),
          totalCount: lines.length,
          chainValid,
        };
      }),
  }),

  runtime: router({
    config: adminProcedure.query(() => ({
      appPort: honeypotConfig.appPort,
      trapPreviewPath: honeypotConfig.trapPreviewPath,
      services: honeypotConfig.services,
      isolation: honeypotConfig.isolation,
    })),
  }),
});

export type AppRouter = typeof appRouter;
