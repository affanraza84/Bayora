import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Bayora Shield — AI Adversarial Security Platform',
  description: 'Multi-enclave red/blue adversarial testing infrastructure with tamper-evident audit logs.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0B0F17] text-gray-100 antialiased selection:bg-red-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
