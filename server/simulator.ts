import "dotenv/config";
import { honeypotEngine } from "./honeypot/engine";

async function run() {
  const count = Number.parseInt(process.env.SIMULATION_COUNT || "16", 10);
  await honeypotEngine.simulateAttackBatch(Number.isFinite(count) ? count : 16);
  console.log(`simulation complete: ${count} synthetic sessions added`);
  process.exit(0);
}

run().catch((error) => {
  console.error("[simulate] failed", error);
  process.exit(1);
});
