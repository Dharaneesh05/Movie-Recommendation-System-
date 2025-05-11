"use client"

import { useRouter } from "next/navigation"
import { useWishlist } from "../../components/WishlistContext"
import Navbar from "../../components/Navbar"
import Footer from "../../components/Footer"
import { useEffect, useState } from "react"

export default function WishlistPage() {
  const router = useRouter()
  const { wishlist, removeFromWishlist } = useWishlist()
  const [username, setUsername] = useState("Guest")

  useEffect(() => {
    const fetchUser = async () => {
      const token = localStorage.getItem("token")
      if (!token) {
        router.push("/login")
        return
      }
      try {
        const res = await fetch("/api/user", {
          headers: { Authorization: `Bearer ${token}` },
        })
        if (!res.ok) throw new Error("Failed to fetch user")
        const data = await res.json()
        if (data.success && data.user) {
          setUsername(data.user.username || "Guest")
        }
      } catch {
        router.push("/login")
      }
    }
    fetchUser()
  }, [router])

  const handleSignOut = () => {
    localStorage.removeItem("token")
    localStorage.removeItem("language")
    localStorage.removeItem("preferences")
    router.push("/login")
  }

  return (
    <div
      className="min-h-screen flex flex-col bg-cover bg-center bg-no-repeat"
      style={{ backgroundImage: "url('/images/cinema-background.jpg')" }}
    >
      <Navbar username={username} onSignOut={handleSignOut} />

      <main className="flex-grow container mx-auto px-4 py-12 bg-black bg-opacity-70 rounded-lg shadow-lg m-4">
        <h1 className="text-5xl font-extrabold text-yellow-400 mb-8 text-center">My Wishlist</h1>

        {wishlist.length === 0 ? (
          <p className="text-center text-gray-300 text-xl">Your wishlist is empty.</p>
        ) : (
          <div className="grid grid-cols-5 gap-6">
            {wishlist.map((movie) => (
              <div key={movie.title} className="relative group border border-gray-700 rounded-lg overflow-hidden shadow-lg bg-gray-900 cursor-default transform transition-transform hover:scale-105 hover:shadow-2xl">
                <img
                  src={movie.poster || "https://placehold.co/200x300?text=No+Poster"}
                  alt={movie.title}
                  className="w-full h-[300px] object-cover"
                />
                <div className="p-3">
                  <h3 className="text-white font-semibold text-lg truncate">{movie.title}</h3>
                  <p className="text-gray-400 text-sm">{movie.language}</p>
                </div>
                <button
                  onClick={() => removeFromWishlist(movie.title)}
                  className="absolute top-2 right-2 bg-red-600 hover:bg-red-700 text-white rounded-full w-8 h-8 flex items-center justify-center opacity-80 group-hover:opacity-100 transition-opacity"
                  aria-label={`Remove ${movie.title} from wishlist`}
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        )}
      </main>

      <Footer />
    </div>
  )
}