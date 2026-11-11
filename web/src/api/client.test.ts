import { describe, it, expect, afterEach, vi } from "vitest";
import {
  AxiosError,
  AxiosHeaders,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from "axios";
import apiClient, {
  ApiError,
  extractApiError,
  loginRedirectURL,
  navigation,
  setCsrfToken,
  toApiError,
} from "./client";

/** Build an AxiosError as axios produces it for a non-2xx response. */
function makeAxiosError(status: number, data?: unknown): AxiosError {
  const headers = new AxiosHeaders();
  const config = {
    headers,
    method: "post",
    url: "/sessions/abc/seal",
    data: JSON.stringify({ secretValue: "hunter2" }),
  } as InternalAxiosRequestConfig;
  return new AxiosError(
    `Request failed with status code ${status}`,
    status >= 500 ? "ERR_BAD_RESPONSE" : "ERR_BAD_REQUEST",
    config,
    {},
    { status, statusText: "error", headers, config, data },
  );
}

function rejectWith(status: number): AxiosAdapter {
  return (config) =>
    Promise.reject(
      new AxiosError(
        "failed",
        "ERR_BAD_REQUEST",
        config,
        {},
        {
          status,
          statusText: "",
          headers: new AxiosHeaders(),
          config,
          data: { error: "unauthorized" },
        },
      ),
    );
}

describe("extractApiError", () => {
  it("returns the server's error text for client errors", () => {
    expect(
      extractApiError(
        makeAxiosError(400, { error: "invalid check-in: bad key" }),
      ),
    ).toBe("invalid check-in: bad key");
    expect(
      extractApiError(
        makeAxiosError(403, { error: "you need write access to acme/infra" }),
      ),
    ).toBe("you need write access to acme/infra");
  });

  it("uses status messages when the body is a bare status word", () => {
    expect(
      extractApiError(makeAxiosError(401, { error: "unauthorized" })),
    ).toBe("Your session has expired — please sign in again");
    expect(
      extractApiError(makeAxiosError(500, { error: "internal error" })),
    ).toBe("The server encountered an error — please try again");
    expect(extractApiError(makeAxiosError(404, { error: "not found" }))).toBe(
      "The requested resource was not found",
    );
  });

  it("shows what a 503 says is unavailable and when to try again", () => {
    expect(
      extractApiError(
        makeAxiosError(503, {
          error:
            "GitHub is limiting the sealer's requests for now; try again in 12 minutes",
        }),
      ),
    ).toBe(
      "GitHub is limiting the sealer's requests for now; try again in 12 minutes",
    );
    // a gateway's own 503 has no such text
    expect(
      extractApiError(makeAxiosError(503, { message: "Service Unavailable" })),
    ).toBe("The service is temporarily unavailable — please try again");
  });

  it("falls back to a status message for non-JSON bodies", () => {
    expect(
      extractApiError(makeAxiosError(502, "<html>Bad Gateway</html>")),
    ).toBe("The server could not complete the request — please try again");
    expect(extractApiError(makeAxiosError(429, "Too Many Requests\n"))).toBe(
      "Too many requests — please wait and try again",
    );
  });

  it("returns a generic message for unknown statuses and non-axios errors", () => {
    expect(extractApiError(makeAxiosError(418))).toBe(
      "An unexpected error occurred. Please try again.",
    );
    expect(extractApiError(new Error("random"))).toBe(
      "An unexpected error occurred. Please try again.",
    );
  });

  it("reports network errors", () => {
    const err = new AxiosError("Network Error", AxiosError.ERR_NETWORK);
    expect(extractApiError(err)).toBe(
      "Unable to reach the server — check your connection and try again",
    );
  });
});

describe("toApiError", () => {
  it("drops the axios config, request and response", () => {
    const err = toApiError(makeAxiosError(422, { error: "bad key" }));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).toBe("bad key");
    expect(err.status).toBe(422);
    for (const prop of ["config", "request", "response", "toJSON"]) {
      expect(err).not.toHaveProperty(prop);
    }
    expect(JSON.stringify(err)).not.toContain("hunter2");
    expect(String(err.stack)).not.toContain("hunter2");
  });
});

describe("apiClient", () => {
  const originalAdapter = apiClient.defaults.adapter;
  const originalAssign = navigation.assign;

  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
    navigation.assign = originalAssign;
    setCsrfToken(null);
    window.history.replaceState({}, "", "/");
  });

  it("sends the CSRF token on unsafe methods only", async () => {
    setCsrfToken("tok+1");
    const seen: Record<string, string | undefined> = {};
    apiClient.defaults.adapter = (config) => {
      seen[config.method ?? ""] =
        config.headers.get("X-CSRF-Token")?.toString() ?? undefined;
      return Promise.resolve({
        data: {},
        status: 200,
        statusText: "OK",
        headers: {},
        config,
      });
    };

    await apiClient.get("/fleet");
    await apiClient.post("/auth/logout");
    await apiClient.delete("/sessions/abc");

    expect(seen.get).toBeUndefined();
    expect(seen.post).toBe("tok+1");
    expect(seen.delete).toBe("tok+1");
  });

  it("marks every request as the page's own", async () => {
    const seen: (string | undefined)[] = [];
    apiClient.defaults.adapter = (config) => {
      seen.push(config.headers.get("X-Requested-With")?.toString());
      return Promise.resolve({
        data: {},
        status: 200,
        statusText: "OK",
        headers: {},
        config,
      });
    };

    await apiClient.get("/repos");
    await apiClient.post("/auth/logout");

    expect(seen).toEqual(["XMLHttpRequest", "XMLHttpRequest"]);
  });

  it("sends a 401 to the login page with the current path to return to", async () => {
    window.history.replaceState({}, "", "/fleet?tab=agents");
    const assign = vi.fn();
    navigation.assign = assign;
    apiClient.defaults.adapter = rejectWith(401);

    const error = await apiClient.get("/fleet").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(assign).toHaveBeenCalledOnce();
    expect(assign).toHaveBeenCalledWith(
      "/login?return_to=%2Ffleet%3Ftab%3Dagents",
    );
  });

  it("does not redirect for /auth/me or from the login page", async () => {
    const assign = vi.fn();
    navigation.assign = assign;
    apiClient.defaults.adapter = rejectWith(401);

    await apiClient.get("/auth/me").catch(() => undefined);
    window.history.replaceState({}, "", "/login?error=not_member");
    await apiClient.get("/fleet").catch(() => undefined);

    expect(assign).not.toHaveBeenCalled();
  });

  it("does not redirect for other errors", async () => {
    const assign = vi.fn();
    navigation.assign = assign;
    apiClient.defaults.adapter = rejectWith(500);
    await apiClient.get("/fleet").catch(() => undefined);
    expect(assign).not.toHaveBeenCalled();
  });
});

describe("loginRedirectURL", () => {
  afterEach(() => window.history.replaceState({}, "", "/"));

  it("omits return_to for the root and the login page", () => {
    window.history.replaceState({}, "", "/");
    expect(loginRedirectURL()).toBe("/login");
    window.history.replaceState({}, "", "/login?return_to=%2Fx");
    expect(loginRedirectURL()).toBe("/login");
  });
});
