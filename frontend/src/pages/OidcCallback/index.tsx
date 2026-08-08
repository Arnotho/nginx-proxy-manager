/**
 * OidcCallback page
 *
 * The backend redirects to /oidc-callback?token=...&expires=... after a successful OIDC login.
 * On error it redirects to /oidc-callback?error=...
 *
 * This page reads those query params and calls loginWithToken() on AuthContext so the
 * React state is updated in-place (no hard page reload needed).
 */
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Page } from "src/components";
import { useAuthState } from "src/context";
import { T } from "src/locale";

export default function OidcCallback() {
	const { loginWithToken } = useAuthState();
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		// Token arrives in the URL fragment (#token=...) so it never touches
		// server logs / browser history; errors arrive in the query string.
		const query = new URLSearchParams(window.location.search);
		const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
		const errorParam = query.get("error") || fragment.get("error");
		const token = fragment.get("token");
		const expires = fragment.get("expires");

		if (errorParam) {
			setError(decodeURIComponent(errorParam));
			return;
		}

		if (token && expires) {
			// Delegate to AuthContext which calls AuthStore.set() and sets authenticated=true
			// without a page reload — avoids race conditions with token refresh timer.
			loginWithToken({ token, expires: expires as unknown as number });
		} else {
			setError("No token received from SSO provider");
		}
	}, [loginWithToken]);

	return (
		<Page className="page page-center">
			<div className="container container-tight py-4">
				<div className="card card-md">
					<div className="card-body text-center">
						{error ? (
							<>
								<Alert variant="danger">
									<T id="login.oidc-error" data={{ message: error }} />
								</Alert>
								<a href="/" className="btn btn-secondary mt-2">
									<T id="login.title" />
								</a>
							</>
						) : (
							<div className="text-secondary">
								<T id="loading" />
							</div>
						)}
					</div>
				</div>
			</div>
		</Page>
	);
}