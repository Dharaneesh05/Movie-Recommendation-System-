"use client"

import React from "react"
import Link from "next/link"
import { useWishlist } from "./WishlistContext"

interface NavbarProps {
  username: string
  onSignOut: () => void
}

export default function Navbar({ username, onSignOut }: NavbarProps) {
  const { wishlist } = useWishlist()

  return (
    <nav className="bg-black bg-opacity-80 backdrop-blur-md fixed top-0 left-0 right-0 z-50 shadow-lg">
      <div className="container mx-auto flex items-center justify-between px-6 py-3">
        <div className="flex items-center space-x-6">
          <Link href="/homepage" legacyBehavior>
            <a className="text-yellow-400 font-extrabold text-2xl tracking-widest hover:text-yellow-500 transition-colors">
              CINEfellas
            </a>
          </Link>
          <Link href="/homepage" legacyBehavior>
            <a className="text-yellow-300 font-semibold hover:text-yellow-400 transition-colors">
              Home
            </a>
          </Link>
        </div>

        <div className="flex items-center space-x-6">
          <Link href="/wishlist" legacyBehavior>
            <a className="text-yellow-400 hover:text-yellow-500 font-semibold focus:outline-none transition-colors">
              My List ({wishlist.length})
            </a>
          </Link>

          <div className="flex items-center space-x-2 text-yellow-400 font-semibold">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-6 w-6"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M5.121 17.804A9 9 0 1118.88 6.196 9 9 0 015.12 17.804z"
              />
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
            <span>Hello, {username}</span>
          </div>

          <button
            onClick={onSignOut}
            className="bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-1.5 px-4 rounded transition-colors shadow-md hover:shadow-lg"
          >
            Sign Out
          </button>
        </div>
      </div>
    </nav>
  )
}
