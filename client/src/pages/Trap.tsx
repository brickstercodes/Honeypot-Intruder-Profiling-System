/**
 * Honey Trap page — rendered server-side via engine.ts renderTrapHtml()
 * This React page is the /trap PREVIEW shown in the admin console.
 * The actual trap served to attackers is pure HTML from the server.
 */
export default function Trap() {
  return (
    <iframe
      src="/trap-preview-frame"
      className="w-full h-screen border-0"
      title="Honey trap preview"
    />
  );
}
