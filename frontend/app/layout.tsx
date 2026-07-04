import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'C2 / SIGNAL — Artifact Scanner',
  description: 'YARA、Sigma 与 Suricata 多引擎制品检测工作台',
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="zh-CN"><body>{children}</body></html>
}
