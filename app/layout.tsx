import type React from "react"
import "./globals.css"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import { WishlistProvider } from "../components/WishlistContext"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "Cinefellas - Your Movie Companion",
  description: "Discover and enjoy movies based on your preferences",
  generator: 'v0.dev'
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className} style={{ margin: 0, padding: 0, position: "relative", minHeight: "100vh" }}>
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            backgroundImage: "url('/images/cinema-background.jpg')",
            backgroundSize: "cover",
            backgroundPosition: "center",
            filter: "blur(8px)",
            zIndex: -1,
          }}
        />
        <WishlistProvider>
          <div style={{ position: "relative", zIndex: 0, minHeight: "100vh" }}>
            {children}
          </div>
        </WishlistProvider>
      </body>
    </html>
  )
}
