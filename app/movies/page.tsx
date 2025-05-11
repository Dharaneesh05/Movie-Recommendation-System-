"use client"

import { useState, useEffect } from "react"
import MovieGrid from "../../components/MovieGrid"
import SearchBar from "../../components/SearchBar"
import { movies } from "../../movies"

interface Movie {
  title: string
  language: string
  genres: string[]
  poster: string | null
}

export default function MoviesPage() {
  const [language, setLanguage] = useState("")
  const [genre, setGenre] = useState("")
  const [searchTerm, setSearchTerm] = useState("")
  const [filteredMovies, setFilteredMovies] = useState<Movie[]>([])

  useEffect(() => {
    const storedLanguage = localStorage.getItem("language")
    if (storedLanguage) {
      setLanguage(storedLanguage)
    }
  }, [])

  useEffect(() => {
    let filtered = movies

    if (language) {
      filtered = filtered.filter(
        (movie) => movie.language.toLowerCase() === language.toLowerCase()
      )
    }

    if (genre) {
      filtered = filtered.filter((movie) =>
        movie.genres.some((g) => g.toLowerCase() === genre.toLowerCase())
      )
    }

    if (searchTerm) {
      const lowerSearch = searchTerm.toLowerCase()
      filtered = filtered.filter((movie) =>
        movie.title.toLowerCase().includes(lowerSearch)
      )
    }

    setFilteredMovies(filtered)
  }, [language, genre, searchTerm])

  return (
    <div
      className="min-h-screen bg-cover bg-center bg-no-repeat flex flex-col items-center px-4 py-8"
      style={{ backgroundImage: "url('/images/cinema-background.jpg')" }}
    >
      <h1 className="text-yellow-400 text-4xl font-extrabold mb-6">Movies</h1>

      <SearchBar
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
        language={language}
        onLanguageChange={setLanguage}
        genre={genre}
        onGenreChange={setGenre}
      />

      <MovieGrid preferences={genre ? [genre] : []} language={language} filteredMovies={filteredMovies} />
    </div>
  )
}
