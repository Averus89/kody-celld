/**
 * First-party HTTP security headers for every server-rendered page
 * (`packages/worker/src/app/security-headers.ts` upstream, minus the
 * third-party analytics / Turnstile / Sentry allowances kody-celld does not
 * ship).
 *
 * - `script-src 'self'` with no `'unsafe-inline'` is the protection that
 *   matters: the browser bundle and `page-init.js` load from this origin, so
 *   an injected inline `<script>` cannot run. Remix's hydration payload is a
 *   `<script type="application/json">` data block, which CSP does not
 *   execute.
 * - `style-src 'unsafe-inline'` because `css()` mixins stream as inline
 *   `<style>` tags during SSR.
 * - `frame-ancestors 'none'` + `X-Frame-Options: DENY` protect the OAuth
 *   consent screen and account pages from clickjacking.
 * - `form-action` keeps browser POSTs on this origin, plus the loopback
 *   redirect URIs MCP clients register for the OAuth code flow. A page whose
 *   form redirects elsewhere over plain http (the MCP OAuth consent page for an
 *   allowlisted LAN authorization server) widens it with
 *   `contentSecurityPolicyWithFormAction`.
 */
const formAction =
	"form-action 'self' https: http://localhost:* http://127.0.0.1:*"

function buildContentSecurityPolicy(formActionDirective: string) {
	return [
		"default-src 'none'",
		"base-uri 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		formActionDirective,
		"img-src 'self' data: https:",
		"font-src 'self' data:",
		"style-src 'self' 'unsafe-inline'",
		"script-src 'self'",
		"connect-src 'self'",
		"manifest-src 'self'",
	].join('; ')
}

const contentSecurityPolicy = buildContentSecurityPolicy(formAction)

/** The first-party CSP with `origins` (bare http(s) origins or scheme sources like `alice:`) added to `form-action`. */
export function contentSecurityPolicyWithFormAction(
	origins: Array<string>,
): string {
	for (const origin of origins) {
		if (
			/^[a-z][a-z0-9+.-]*:$/.test(origin) &&
			origin !== 'javascript:' &&
			origin !== 'data:'
		)
			continue
		let parsed: URL | null = null
		try {
			parsed = new URL(origin)
		} catch {
			/* refused below */
		}
		if (
			!parsed ||
			(parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
			parsed.origin !== origin
		) {
			throw new Error(
				`form-action source must be a bare http(s) origin, got "${origin}".`,
			)
		}
	}
	return origins.length
		? buildContentSecurityPolicy(`${formAction} ${origins.join(' ')}`)
		: contentSecurityPolicy
}

/**
 * The form-action source an OAuth consent page needs so Approve / Deny can
 * redirect to `redirectUri`, or null when the base policy already allows it.
 * Private-use schemes (`alice://`, `cursor://`) give their scheme; other http
 * loopback hosts (`*.localhost`) their origin. CSP host-source cannot name an
 * IPv6 literal, so `http://[::1]` gives `http:` for that one page.
 */
export function formActionSourceForRedirect(
	redirectUri: string,
): string | null {
	const url = new URL(redirectUri)
	if (url.protocol === 'https:') return null
	if (url.protocol === 'http:') {
		if (url.hostname === 'localhost' || url.hostname === '127.0.0.1')
			return null
		return url.hostname.startsWith('[') ? 'http:' : url.origin
	}
	if (!/^[a-z][a-z0-9+.-]*:$/.test(url.protocol)) {
		throw new Error(`form-action scheme is not valid, got "${url.protocol}".`)
	}
	return url.protocol
}

export const firstPartySecurityHeaders: Readonly<Record<string, string>> = {
	'content-security-policy': contentSecurityPolicy,
	'x-frame-options': 'DENY',
	'x-content-type-options': 'nosniff',
	'referrer-policy': 'same-origin',
	'cache-control': 'no-store',
}

/**
 * Headers for a server-rendered page. Page overrides replace first-party
 * defaults by name (one `content-security-policy` header, never two that
 * browsers would intersect). Keys are lowercased via `Headers`.
 */
export function pageResponseHeaders(
	overrides?: HeadersInit,
): Record<string, string> {
	return {
		'content-type': 'text/html; charset=utf-8',
		...firstPartySecurityHeaders,
		...Object.fromEntries(new Headers(overrides ?? {}).entries()),
	}
}
