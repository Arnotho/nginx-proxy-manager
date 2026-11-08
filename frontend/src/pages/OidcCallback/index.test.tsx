import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { type ReactNode, StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import OidcCallback from "./index";

const { completeOidcLogin } = vi.hoisted(() => ({ completeOidcLogin: vi.fn() }));
vi.mock("src/context", () => ({ useAuthState: () => ({ completeOidcLogin }) }));
vi.mock("src/components", () => ({ Page: ({ children }: { children: ReactNode }) => children }));
vi.mock("src/locale", () => ({
	T: ({ id, data }: { id: string; data?: { message?: string } }) => <>{data?.message || id}</>,
}));

describe("OIDC callback", () => {
	beforeEach(() => {
		completeOidcLogin.mockReset().mockResolvedValue(undefined);
		window.history.replaceState(null, "", "/oidc-callback");
	});
	afterEach(cleanup);

	it("exchanges the server cookie once in StrictMode and removes injected URL credentials", async () => {
		window.history.replaceState(null, "", "/oidc-callback#token=attacker-token&expires=2099");
		render(
			<StrictMode>
				<OidcCallback />
			</StrictMode>,
		);
		await waitFor(() => expect(completeOidcLogin).toHaveBeenCalledTimes(1));
		expect(completeOidcLogin).toHaveBeenCalledWith();
		expect(window.location.hash).toBe("");
	});

	it("displays an error without double decoding or exchanging a failed login", async () => {
		window.history.replaceState(null, "", "/oidc-callback?error=failed%20at%20100%25");
		render(<OidcCallback />);
		expect(await screen.findByText("failed at 100%")).toBeVisible();
		expect(completeOidcLogin).not.toHaveBeenCalled();
		expect(window.location.search).toBe("");
	});

	it("handles an expired or missing cookie instead of accepting a URL token", async () => {
		completeOidcLogin.mockRejectedValue(new Error("expired"));
		render(<OidcCallback />);
		expect(await screen.findByText("SSO authentication failed. Please start again.")).toBeVisible();
	});
});
