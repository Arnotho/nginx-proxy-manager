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
		const params = new URLSearchParams(window.location.search);
		const errorParam = params.get("error");
		const token = params.get("token");
		const expires = params.get("expires");

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