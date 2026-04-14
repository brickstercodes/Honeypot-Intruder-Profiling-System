import { z } from "zod";
import { honeypotConfig } from "./honeypot/config";
import { honeypotEngine } from "./honeypot/engine";
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