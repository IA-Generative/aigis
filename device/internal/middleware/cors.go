package middleware

import (
	"net/http"
	"strconv"
	"strings"
)

type CORSOptions struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAgeSeconds    int
}

func CORS(opts CORSOptions) func(http.Handler) http.Handler {
	originSet := map[string]struct{}{}
	allowAllOrigins := false
	for _, origin := range opts.AllowedOrigins {
		if origin == "*" {
			allowAllOrigins = true
			continue
		}
		originSet[origin] = struct{}{}
	}

	allowedMethods := strings.Join(opts.AllowedMethods, ", ")
	allowedHeaders := strings.Join(opts.AllowedHeaders, ", ")
	exposedHeaders := strings.Join(opts.ExposedHeaders, ", ")
	maxAge := strconv.Itoa(opts.MaxAgeSeconds)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			_, explicitlyAllowed := originSet[origin]
			if !allowAllOrigins && !explicitlyAllowed {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			if allowAllOrigins && !opts.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			if opts.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			if exposedHeaders != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposedHeaders)
			}

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				if allowedMethods != "" {
					w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
				}
				if allowedHeaders != "" {
					w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
				}
				if opts.MaxAgeSeconds > 0 {
					w.Header().Set("Access-Control-Max-Age", maxAge)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
