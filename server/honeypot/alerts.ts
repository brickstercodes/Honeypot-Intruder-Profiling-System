import type { AlertRecord } from "@shared/honeypot";
import type { HoneypotConfig } from "./config";

const postJson = async (url: string, body: unknown, headers?: Record<string, string>) => {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(headers || {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Alert delivery failed (${response.status})`);
  }
};

export async function deliverAlert(
  alert: AlertRecord,
  config: HoneypotConfig
): Promise<string[]> {
  const delivered: string[] = [];

  if (config.alerting.dashboard) {
    delivered.push("dashboard");
  }

  if (config.alerting.discordWebhookUrl) {
    try {
      await postJson(config.alerting.discordWebhookUrl, {
        username: "Honeypot IDS",
        embeds: [
          {
            title: alert.title,
            description: alert.message,
            color:
              alert.severity === "critical"
                ? 0xdc2626
                : alert.severity === "high"
                  ? 0xea580c
                  : alert.severity === "medium"
                    ? 0xd97706
                    : 0x16a34a,
          },
        ],
      });
      delivered.push("discord");
    } catch (error) {
      console.warn("[Alert] Discord delivery failed", error);
    }
  }

  if (config.alerting.telegramBotToken && config.alerting.telegramChatId) {
    try {
      await postJson(
        `https://api.telegram.org/bot${config.alerting.telegramBotToken}/sendMessage`,
        {
          chat_id: config.alerting.telegramChatId,
          text: `${alert.title}\n${alert.message}`,
        }
      );
      delivered.push("telegram");
    } catch (error) {
      console.warn("[Alert] Telegram delivery failed", error);
    }
  }

  if (
    config.alerting.resendApiKey &&
    config.alerting.alertEmailTo &&
    config.alerting.alertEmailFrom
  ) {
    try {
      await postJson(
        "https://api.resend.com/emails",
        {
          from: config.alerting.alertEmailFrom,
          to: [config.alerting.alertEmailTo],
          subject: alert.title,
          text: alert.message,
        },
        {
          Authorization: `Bearer ${config.alerting.resendApiKey}`,
        }
      );
      delivered.push("email");
    } catch (error) {
      console.warn("[Alert] Email delivery failed", error);
    }
  }

  return delivered;
}
