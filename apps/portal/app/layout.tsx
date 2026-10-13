import type { ReactNode } from "react";

export const metadata = {
  title: "Community CTI",
  description: "Findings for your organisation.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en-AU">
      <body style={{ fontFamily: "system-ui, sans-serif", color: "#111", background: "#fff", margin: "1rem" }}>
        {children}
      </body>
    </html>
  );
}
