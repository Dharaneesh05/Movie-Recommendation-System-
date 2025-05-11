interface Movie {
  title: string
  language: string
  genres: string[]
  poster: string | null
}

export const movies: Movie[] = [
  { title: "Vikram", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Thuppakki", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Mersal", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Theri", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Bigil", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Sarkar", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Master", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Darbar", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Kabali", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Petta", language: "Tamil", genres: ["Action"], poster: null },
  { title: "Mad Max: Fury Road", language: "English", genres: ["Action"], poster: null },
  { title: "John Wick", language: "English", genres: ["Action"], poster: null },
  { title: "The Dark Knight", language: "English", genres: ["Action"], poster: null },
  { title: "Gladiator", language: "English", genres: ["Action"], poster: null },
  { title: "Inception", language: "English", genres: ["Action"], poster: null },
  { title: "The Matrix", language: "English", genres: ["Action"], poster: null },
  { title: "Die Hard", language: "English", genres: ["Action"], poster: null },
  { title: "Mission: Impossible - Fallout", language: "English", genres: ["Action"], poster: null },
  { title: "Skyfall", language: "English", genres: ["Action"], poster: null },
  { title: "Terminator 2: Judgment Day", language: "English", genres: ["Action"], poster: null },
  // ... more movies (truncated for brevity)
]

const API_KEY = process.env.NEXT_PUBLIC_TMDB_API_KEY || "cfa42dd031421ea1a883a9a8d19d46ed"
const BASE_IMAGE_URL = "https://image.tmdb.org/t/p/w500"

async function fetchWithRetry(url: string, retries = 2, delay = 500) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), 10000) // 10-second timeout

  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, { signal: controller.signal })
      clearTimeout(timeoutId)
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`)
      }
      return response
    } catch (error) {
      clearTimeout(timeoutId)
      if (i === retries - 1) throw error // Last retry
      console.warn(`Retrying fetch (${i + 1}/${retries}) for ${url}: ${error}`)
      await new Promise((resolve) => setTimeout(resolve, delay))
    }
  }
  throw new Error("Fetch failed after retries")
}

export async function fetchMoviePosters(filteredMovies: Movie[]): Promise<Movie[]> {
  const languageCodeMap: Record<string, string> = {
    Tamil: "ta",
    Telugu: "te",
    Hindi: "hi",
    Malayalam: "ml",
    Kannada: "kn",
    English: "en",
  }

  const fetchPromises = filteredMovies.map(async (movie) => {
    try {
      const languageCode = languageCodeMap[movie.language] || "en"
      console.log(`Fetching poster for ${movie.title} in language ${languageCode}...`)

      const url = `https://api.themoviedb.org/3/search/movie?api_key=${API_KEY}&query=${encodeURIComponent(movie.title)}&language=${languageCode}`
      const response = await fetchWithRetry(url)

      const data = await response.json()

      if (data.results && data.results.length > 0) {
        const matchedMovie =
          data.results.find((result: any) => result.original_language === languageCode) || data.results[0]

        const posterPath = matchedMovie.poster_path

        if (posterPath) {
          movie.poster = `${BASE_IMAGE_URL}${posterPath}`
          console.log(`Poster found for ${movie.title}: ${movie.poster}`)
        } else {
          movie.poster = "https://placehold.co/500x750?text=No+Poster"
          console.log(`No poster found for ${movie.title}, using fallback.`)
        }
      } else {
        movie.poster = "https://placehold.co/500x750?text=Movie+Not+Found"
        console.log(`Movie not found for ${movie.title}, using fallback.`)
      }
    } catch (error) {
      console.error(`Error fetching poster for ${movie.title}:`, error)
      movie.poster = "https://placehold.co/500x750?text=Error"
    }

    return movie
  })

  return Promise.all(fetchPromises)
}
