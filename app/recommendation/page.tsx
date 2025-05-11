"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import Navbar from "../../components/Navbar"
import MovieGrid from "../../components/MovieGrid"
import Footer from "../../components/Footer"
import { movies } from "../../movies"

interface UserData {
  username: string
  preferences: string[]
  language: string
}

export default function RecommendationPage() {
  const router = useRouter()
  const [userData, setUserData] = useState<UserData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [recommendedMovies, setRecommendedMovies] = useState<typeof movies>([])

  useEffect(() => {
    const fetchUserData = async () => {
      const token = localStorage.getItem("token")

      if (!token) {
        router.push("/login")
        return
      }

      try {
        const res = await fetch("/api/user", {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        })

        if (!res.ok) {
          throw new Error(`HTTP error! Status: ${res.status}`)
        }

        const data = await res.json()

        if (data.success && data.user) {
          setUserData({
            username: data.user.username || "Guest",
            preferences: data.user.preferences || ["Action", "Comedy", "Drama"],
            language: data.user.language || "English",
          })
        } else {
          throw new Error(data.message || "Failed to fetch user data")
        }
      } catch (error) {
        console.error("Error fetching user data:", error)
        router.push("/login")
      } finally {
        setIsLoading(false)
      }
    }

    fetchUserData()
  }, [router])

  useEffect(() => {
    if (!userData) return

    // Get filtered movie titles from localStorage
    const filteredTitlesStr = localStorage.getItem("filteredMovies")
    let filteredTitles: string[] = []
    if (filteredTitlesStr) {
      try {
        filteredTitles = JSON.parse(filteredTitlesStr)
      } catch {
        filteredTitles = []
      }
    }

    // Filter movies based on filteredTitles if available, else fallback to user preferences
    let filtered: typeof movies = []
    if (filteredTitles.length > 0) {
      filtered = movies.filter((movie) => filteredTitles.includes(movie.title))
    } else {
      filtered = movies.filter(
        (movie) =>
          movie.language.toLowerCase() === userData.language.toLowerCase() &&
          movie.genres.some((genre) =>
            userData.preferences.some((pref) => pref.toLowerCase() === genre.toLowerCase())
          )
      )
    }

    // Pick one or two random movies from filtered list
    const count = Math.min(2, filtered.length)
    const shuffled = filtered.sort(() => 0.5 - Math.random())
    setRecommendedMovies(shuffled.slice(0, count))
  }, [userData])

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen relative">
      <div
        className="fixed top-0 left-0 w-full h-full bg-cover bg-center filter blur-sm -z-10"
        style={{ backgroundImage: "url('/images/cinema-background.jpg')" }}
      />
      <Navbar username={userData?.username || "Guest"} onSignOut={() => router.push("/login")} />

      <main className="flex-grow container mx-auto px-4 py-12 bg-black bg-opacity-50 rounded-lg shadow-lg m-4 backdrop-blur-sm relative z-10">
        <header className="text-center mb-6">
          <h1 className="text-5xl font-extrabold text-yellow-400 mb-4 drop-shadow-lg">Recommended for You</h1>
          <p className="text-lg text-gray-300 drop-shadow-sm">Based on your preferences and language</p>
        </header>

        <section>
          {recommendedMovies.length > 0 ? (
            <MovieGrid
              filteredMovies={recommendedMovies}
              preferences={userData?.preferences || []}
              language={userData?.language || ""}
            />
          ) : (
            <p className="text-center text-white text-xl">No recommendations available.</p>
          )}
        </section>
      </main>

      <Footer />
    </div>
  )
}
