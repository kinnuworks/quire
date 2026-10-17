import type { ReactNode } from "react"

/** Lucide-style icons: 24px grid, 1.75 stroke, round caps. Inline so the app stays self-contained. */
function Icon({ children, size = 19 }: { children: ReactNode; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {children}
    </svg>
  )
}

export const LockIcon = () => (
  <Icon>
    <rect x="4" y="11" width="16" height="10" rx="2" />
    <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  </Icon>
)
export const PenIcon = () => (
  <Icon>
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z" />
  </Icon>
)
export const HourglassIcon = () => (
  <Icon>
    <path d="M5 22h14M5 2h14" />
    <path d="M17 22v-4.2a2 2 0 0 0-.6-1.4L12 12l-4.4 4.4a2 2 0 0 0-.6 1.4V22M7 2v4.2a2 2 0 0 0 .6 1.4L12 12l4.4-4.4a2 2 0 0 0 .6-1.4V2" />
  </Icon>
)
export const KeyIcon = () => (
  <Icon>
    <circle cx="7.5" cy="15.5" r="4.5" />
    <path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3" />
  </Icon>
)
export const PlugIcon = () => (
  <Icon>
    <path d="M12 22v-5M9 8V2M15 8V2" />
    <path d="M18 8v5a6 6 0 0 1-12 0V8Z" />
  </Icon>
)
export const BookIcon = () => (
  <Icon>
    <path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20" />
  </Icon>
)
export const TerminalIcon = () => (
  <Icon>
    <path d="m4 17 6-6-6-6M12 19h8" />
  </Icon>
)
export const HistoryIcon = () => (
  <Icon>
    <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
    <path d="M3 3v5h5M12 7v5l4 2" />
  </Icon>
)
export const SnowIcon = () => (
  <Icon>
    <path d="M12 2v20M2 12h20M5 5l14 14M19 5 5 19" />
  </Icon>
)
export const ShieldIcon = () => (
  <Icon>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
    <path d="m9 12 2 2 4-4" />
  </Icon>
)
export const ArrowIcon = () => (
  <Icon size={17}>
    <path d="M5 12h14M13 6l6 6-6 6" />
  </Icon>
)
export const GithubIcon = () => (
  <Icon size={17}>
    <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.9a3.4 3.4 0 0 0-.9-2.6c3.1-.4 6.4-1.5 6.4-6.8A5.3 5.3 0 0 0 20 4.8 4.9 4.9 0 0 0 19.9 1S18.7.7 16 2.5a13.4 13.4 0 0 0-7 0C6.3.7 5.1 1 5.1 1A4.9 4.9 0 0 0 5 4.8a5.3 5.3 0 0 0-1.5 3.7c0 5.3 3.3 6.4 6.4 6.8A3.4 3.4 0 0 0 9 18v4" />
  </Icon>
)
