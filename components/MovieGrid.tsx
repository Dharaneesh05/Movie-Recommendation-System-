"use client"

import { useEffect, useState } from "react"
import { fetchMoviePosters, movies } from "../movies"
import { useWishlist } from "./WishlistContext"

interface MovieGridProps {
  preferences: string[]
  language: string
  filteredMovies?: Movie[]
}

interface Movie {
  title: string
  language: string
  genres: string[]
  poster: string | null
}

export default function MovieGrid({ preferences, language, filteredMovies: filteredMoviesProp }: MovieGridProps) {
  const [filteredMovies, setFilteredMovies] = useState<Movie[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const { wishlist, addToWishlist, removeFromWishlist, isInWishlist } = useWishlist()

  useEffect(() => {
    const filterMovies = () => {
      let prefs: string[] = preferences
      if (!prefs || !prefs.length) {
        prefs = ["Action", "Comedy", "Drama"]
      }
      if (!language) {
        language = "English"
      }

      const prefArray = Array.isArray(prefs)
        ? prefs
        : prefs
            .toString()
            .split(",")
            .map((p: string) => p.trim())

      const filtered = movies.filter((movie) => {
        if (!movie.genres || !Array.isArray(movie.genres)) {
          return false
        }
        if (!movie.language) {
          return false
        }

        const genreMatch = movie.genres.some((genre) =>
          prefArray.some((pref: string) => pref.toLowerCase() === genre.toLowerCase()),
        )
        const languageMatch = movie.language.toLowerCase() === language.toLowerCase()

        return genreMatch && languageMatch
      })

      return filtered.slice(0, 10)
    }

    const loadMovies = async (moviesToLoad: Movie[]) => {
      setIsLoading(true)
      setFilteredMovies(moviesToLoad)

      const updatePoster = (title: string, posterUrl: string) => {
        setFilteredMovies((prevMovies) =>
          prevMovies.map((movie) =>
            movie.title === title ? { ...movie, poster: posterUrl } : movie,
          ),
        )
      }

      try {
        await fetchMoviePosters(moviesToLoad, updatePoster)
      } catch (error) {
        console.error("Error fetching posters:", error)
      }

      setIsLoading(false)
    }

    if (filteredMoviesProp && filteredMoviesProp.length > 0) {
      loadMovies(filteredMoviesProp)
    } else {
      const filtered = filterMovies()
      loadMovies(filtered)
    }
  }, [preferences, language, filteredMoviesProp])

  if (isLoading) {
    return (
      <div id="loadingIndicator" className="text-center py-5">
        <p className="text-white">Loading posters...</p>
      </div>
    )
  }

  if (filteredMovies.length === 0) {
    return (
      <div className="text-center py-5">
        <p className="text-white">No movies match your preferences and language.</p>
      </div>
    )
  }

  return (
    <div className="movie-grid grid grid-cols-5 grid-rows-2 gap-6 p-5 max-w-5xl mx-auto">
      {filteredMovies.map((movie, index) => {
        const inWishlist = isInWishlist(movie.title)
        return (
          <div
            key={`${movie.title}-${index}`}
            className="relative group border border-gray-700 rounded-lg overflow-hidden shadow-lg bg-gray-900 transform transition-transform hover:scale-105 hover:shadow-2xl"
          >
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
              onClick={() => (inWishlist ? removeFromWishlist(movie.title) : addToWishlist(movie))}
              className="absolute top-2 right-2 text-yellow-400 hover:text-yellow-500 focus:outline-none"
              aria-label={inWishlist ? "Remove from wishlist" : "Add to wishlist"}
              title={inWishlist ? "Remove from wishlist" : "Add to wishlist"}
            >
              {inWishlist ? (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-7 w-7 fill-current" viewBox="0 0 24 24">
                  <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41 0.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" />
                </svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-7 w-7 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41 0.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" />
                </svg>
              )}
            </button>
          </div>
        )
      })}
    </div>
  )
}
