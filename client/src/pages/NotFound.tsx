import { useLocation } from "wouter";

export default function NotFound() {
  const [, navigate] = useLocation();

  return (
    <div className="console-shell flex min-h-screen items-center justify-center px-4 py-5 text-slate-100 md:px-6 xl:px-8">
      <div className="panel max-w-xl text-center">
        <div className="eyebrow">404</div>
        <h1 className="mt-4 text-4xl font-semibold tracking-[-0.04em] text-white">
          Route gone.
        </h1>
        <p className="mt-3 text-sm leading-7 text-slate-300">
          This path has no control surface behind it.
        </p>
        <div className="mt-8 flex justify-center">
          <button className="action-button" onClick={() => navigate("/")}>
            Return home
          </button>
        </div>
      </div>
    </div>
  );
}
