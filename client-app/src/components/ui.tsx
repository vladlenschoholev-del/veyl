import type { ButtonHTMLAttributes, PropsWithChildren } from "react";

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  return (
    <button
      className={`button button-${variant} ${className}`}
      {...props}
    />
  );
}

export function Panel({
  children,
  className = "",
}: PropsWithChildren<{ className?: string }>) {
  return <section className={`panel ${className}`}>{children}</section>;
}

export function Pill({
  children,
  tone = "neutral",
}: PropsWithChildren<{ tone?: "neutral" | "green" | "amber" | "red" }>) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function Icon({
  children,
  className = "",
}: PropsWithChildren<{ className?: string }>) {
  return <span className={`icon ${className}`} aria-hidden="true">{children}</span>;
}
