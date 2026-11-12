import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Dilli Haat SMS Campaign (DHSC) — Bulk SMS Manager",
  description:
    "Fail-safe Bulk SMS Campaign Management Web Application backed by Supabase PostgreSQL + Edge Functions integrating with sms-rest 3.0.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-slate-50 text-slate-900">
        {children}
      </body>
    </html>
  );
}
