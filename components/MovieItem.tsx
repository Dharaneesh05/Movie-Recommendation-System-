interface MovieItemProps {
  movie: {
    title: string
    poster: string | null
  }
}

export default function MovieItem({ movie }: MovieItemProps) {
  const placeholderSrc = `https://placehold.co/200x300?text=${encodeURIComponent(movie.title)}`
  const posterSrc = movie.poster || placeholderSrc

  return (
    <div className="movie-item relative w-full pb-[150%] bg-gray-800 rounded-lg overflow-hidden cursor-pointer transition-transform hover:scale-105">
      <img
        src={posterSrc || "/placeholder.svg"}
        alt={movie.title}
        className="absolute top-0 left-0 w-full h-full object-cover transition-opacity hover:opacity-70"
        onError={(e) => {
          const target = e.target as HTMLImageElement
          target.src = placeholderSrc
        }}
      />
      <div className="overlay absolute bottom-0 left-0 w-full bg-black/70 text-white p-2 opacity-0 transition-opacity hover:opacity-100 flex justify-center items-center">
        <div className="play-btn text-2xl text-white cursor-pointer">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-8 w-8"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
            />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
      </div>
    </div>
  )
}
