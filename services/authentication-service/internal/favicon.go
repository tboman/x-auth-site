package internal

import "net/http"

// xAuthFaviconSVG is the X-Auth brand mark used as the favicon on every hosted
// page (auth.x-auth.com): a bold accent-green "X" on a dark rounded square,
// echoing the site's "X-AUTH//" wordmark (accent #00e096 on #09090b). An SVG
// scales crisply from the 16px browser tab up to any retina size.
const xAuthFaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" role="img" aria-label="X-Auth">
<rect width="32" height="32" rx="7" fill="#0c0c0f"/>
<g fill="none" stroke="#00e096" stroke-width="3.6" stroke-linecap="round">
<path d="M10 10L22 22"/>
<path d="M22 10L10 22"/>
</g>
</svg>`

// faviconLinkTag is the <head> element that points browsers at the SVG favicon.
// Injected into each hosted page's head; the /favicon.ico route below also
// covers the browser's automatic probe for anything that doesn't read the link.
const faviconLinkTag = `<link rel="icon" type="image/svg+xml" href="/favicon.svg">`

// Favicon serves the X-Auth logo. Registered for both /favicon.svg (referenced
// by the head link) and /favicon.ico (the default browser probe) — modern
// browsers render the SVG returned at either path.
func Favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(xAuthFaviconSVG))
}
