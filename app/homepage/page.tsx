"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import Navbar from "../../components/Navbar"
import MovieGrid from "../../components/MovieGrid"
import Footer from "../../components/Footer"
import SearchBar from "../../components/SearchBar"
import { movies } from "../../movies"

interface UserData {
  username: string
  preferences: string[]
  language: string
}

export default function HomePage() {
  const router = useRouter()
  const [userData, setUserData] = useState<UserData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState("")
  const [language, setLanguage] = useState("")
  const [genre, setGenre] = useState("")
  const [filteredMovies, setFilteredMovies] = useState<typeof movies>([])

  useEffect(() => {
    const fetchUserData = async () => {
      const token = localStorage.getItem("token")

      if (!token) {
        console.error("No token found in localStorage")
        setTimeout(() => {
          router.push("/login")
        }, 1000)
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
          setLanguage(data.user.language || "English")
          setGenre(data.user.preferences && data.user.preferences.length > 0 ? data.user.preferences[0] : "")
          localStorage.setItem("language", data.user.language || "English")
          localStorage.setItem("genre", data.user.preferences && data.user.preferences.length > 0 ? data.user.preferences[0] : "")
        } else {
          throw new Error(data.message || "Failed to fetch user data")
        }
      } catch (error) {
        console.error("Error fetching user data:", error)
        setTimeout(() => {
          router.push("/login")
        }, 1000)
      } finally {
        setIsLoading(false)
      }
    }

    fetchUserData()
  }, [router])

  useEffect(() => {
    if (!searchTerm && !language && !genre) {
      setFilteredMovies([])
      return
    }
    const lowerSearch = searchTerm.toLowerCase()
    const filtered = movies.filter((movie) => {
      const matchesSearch =
        movie.title.toLowerCase().includes(lowerSearch) ||
        movie.genres.some((g) => g.toLowerCase().includes(lowerSearch))
      const matchesLanguage = language ? movie.language.toLowerCase() === language.toLowerCase() : true
      const matchesGenre = genre ? movie.genres.some((g) => g.toLowerCase() === genre.toLowerCase()) : true
      return matchesSearch && matchesLanguage && matchesGenre
    })
    setFilteredMovies(filtered)
    localStorage.setItem("language", language)
    localStorage.setItem("genre", genre)
    localStorage.setItem("searchTerm", searchTerm)
  }, [searchTerm, language, genre])

  const handleSignOut = () => {
    localStorage.removeItem("token")
    localStorage.removeItem("language")
    localStorage.removeItem("preferences")
    localStorage.removeItem("genre")
    localStorage.removeItem("searchTerm")
    router.push("/login")
  }

  const handleRecommendMovie = () => {
    // Store filtered movies titles in localStorage for recommendation page
    const filteredTitles = filteredMovies.map((movie) => movie.title)
    localStorage.setItem("filteredMovies", JSON.stringify(filteredTitles))
    router.push("/recommendation")
  }

  useEffect(() => {
    // Load filters from localStorage on mount
    const storedLanguage = localStorage.getItem("language")
    const storedGenre = localStorage.getItem("genre")
    const storedSearchTerm = localStorage.getItem("searchTerm")
    if (storedLanguage) setLanguage(storedLanguage)
    if (storedGenre) setGenre(storedGenre)
    if (storedSearchTerm) setSearchTerm(storedSearchTerm)
  }, [])

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
      <Navbar username={userData?.username || "Guest"} onSignOut={handleSignOut} />

      <main className="flex-grow container mx-auto px-4 py-12 bg-black bg-opacity-50 rounded-lg shadow-lg m-4 backdrop-blur-sm relative z-10">
        <header className="text-center mb-6">
          <h1 className="text-5xl font-extrabold text-yellow-400 mb-4 drop-shadow-lg">Popular Movies and Shows</h1>
          <p className="text-lg text-gray-300 drop-shadow-sm">Watch the best content from all genres</p>
        </header>

        <SearchBar
          searchTerm={searchTerm}
          onSearchChange={setSearchTerm}
          language={language}
          onLanguageChange={setLanguage}
          genre={genre}
          onGenreChange={setGenre}
        />

        <section>
          {userData && (
            <MovieGrid
              preferences={genre ? [genre] : userData.preferences}
              language={language || userData.language}
              filteredMovies={filteredMovies.length > 0 ? filteredMovies : undefined}
            />
          )}
        </section>

        <div className="text-center mt-10">
          <button
            onClick={handleRecommendMovie}
            className="bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-3 px-8 rounded-lg text-xl transition-colors shadow-lg hover:shadow-xl transform hover:-translate-y-1"
          >
            Pick a Movie for Me
          </button>
        </div>
      </main>

      <Footer />
    </div>
  )
}
