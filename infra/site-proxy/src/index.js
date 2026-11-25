/**
 * Edge proxy for the routing-rules site.
 *
 * GitHub Pages can only serve a project site at `/<repo>/` on `<user>.github.io`,
 * and GitHub Pages has no notion of hosting a project at a sub-path of a custom
 * domain. This Worker publishes the same build output at
 * `https://proxy.distinctive.fun/routing/` by forwarding to GitHub Pages and
 * rewriting only the origin prefix.
 *
 * Build output is generated with `--base-url https://proxy.distinctive.fun/routing`,
 * so absolute links (subscription URLs) already point at the custom domain and
 * relative links resolve correctly under the `/routing/` prefix.
 */

const ORIGIN_ORIGIN = "https://yuyu1025.github.io";
const ORIGIN_PREFIX = "/routing-rules";
const PUBLIC_PREFIX = "/routing";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
]);

function buildOriginRequest(request) {
  const url = new URL(request.url);
  const suffix = url.pathname.slice(PUBLIC_PREFIX.length);
  const target = new URL(ORIGIN_ORIGIN + ORIGIN_PREFIX + suffix);
  target.search = url.search;

  const headers = new Headers();
  for (const [key, value] of request.headers) {
    if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  }
  headers.set("host", ORIGIN_ORIGIN.replace("https://", ""));

  return new Request(target, {
    method: request.method,
    headers,
    redirect: "manual",
  });
}

function rewriteLocation(value) {
  if (!value) return value;
  try {
    const location = new URL(value, ORIGIN_ORIGIN);
    if (location.origin !== ORIGIN_ORIGIN) return value;
    if (!location.pathname.startsWith(ORIGIN_PREFIX)) return value;
    const suffix = location.pathname.slice(ORIGIN_PREFIX.length);
    return PUBLIC_PREFIX + suffix + location.search;
  } catch {
    return value;
  }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed\n", {
        status: 405,
        headers: { "content-type": "text/plain; charset=utf-8", allow: "GET, HEAD" },
      });
    }

    if (pathname === "/" || pathname === "") {
      return Response.redirect(url.origin + PUBLIC_PREFIX + "/", 302);
    }

    if (pathname === PUBLIC_PREFIX) {
      return Response.redirect(url.origin + PUBLIC_PREFIX + "/" + url.search, 301);
    }

    if (!pathname.startsWith(PUBLIC_PREFIX + "/")) {
      return new Response("Not Found\n", {
        status: 404,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    const originRequest = buildOriginRequest(request);
    const response = await fetch(originRequest, {
      cf: {
        cacheEverything: true,
        cacheTtlByStatus: { "200-299": 60, "404": 60 },
      },
    });

    const headers = new Headers(response.headers);
    headers.delete("set-cookie");
    headers.delete("content-security-policy");
    headers.delete("content-security-policy-report-only");
    headers.delete("x-github-request-id");
    headers.delete("x-served-by");
    const location = headers.get("location");
    if (location) headers.set("location", rewriteLocation(location));
    headers.set("x-routing-rules-proxy", "1");

    return new Response(request.method === "HEAD" ? null : response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};
