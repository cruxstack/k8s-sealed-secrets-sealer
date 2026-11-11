package httpserver

import "net/http"

// contentSecurityPolicy allows only same-origin scripts, fonts and
// connections; images may also come from GitHub avatars. Scripts are never
// inline. Styles may be: Radix menus and dialogs add a small <style> element
// while open (to lock page scrolling) whose content varies, so it cannot be
// hashed, and injected CSS is a far smaller risk than injected script.
// Forms post to the same origin, and to formActions besides: the GitHub
// App setup page posts its manifest to GitHub.
func contentSecurityPolicy(formActions []string) string {
	formAction := "'self'"
	for _, o := range formActions {
		formAction += " " + o
	}
	return "default-src 'none'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: https://avatars.githubusercontent.com; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"manifest-src 'self'; " +
		"base-uri 'none'; " +
		"form-action " + formAction + "; " +
		"frame-ancestors 'none'"
}

// SecurityHeaders sets browser security headers on every response. hsts
// turns on Strict-Transport-Security, for deployments served over https;
// formActions are origins forms may post to besides the page's own (only
// while the GitHub App is set up).
func SecurityHeaders(hsts bool, formActions ...string) func(http.Handler) http.Handler {
	csp := contentSecurityPolicy(formActions)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}
