import type { ReactNode } from "react";
export function Brand() {
  return (
    <div className="brand">
      <svg width="36" height="38" viewBox="0 0 36 38" aria-hidden="true">
        <path
          d="M11 22C12 9 23 6 27 4M25 5c-7-2-9 1-10 5 5 1 9-1 10-5Z"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        />
        <circle cx="10" cy="25" r="8" fill="#ef6470" />
        <circle cx="26" cy="25" r="8" fill="#d73f52" />
      </svg>
      <span>
        Cherry<span className="brand-light">Security</span>
        <small>CONSOLE</small>
      </span>
    </div>
  );
}
export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon" aria-hidden="true">
        ◇
      </div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
export function Panel({
  title,
  description,
  children,
  action,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function ErrorNotice({ message }: { message: string }) {
  return message ? (
    <div className="notice error" role="alert">
      {message}
    </div>
  ) : null;
}
