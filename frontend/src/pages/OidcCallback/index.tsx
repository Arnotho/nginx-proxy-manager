import { useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Page } from "src/components";
import { useAuthState } from "src/context";
import { T } from "src/locale";

export default function OidcCallback() {
	const { completeOidcLogin } = useAuthState();
	const [error, setError] = useState<string | null>(null);

	const started = useRef(false);
	useEffect(() => {
		if (started.current) return;
		started.current = true;
		const query = new URLSearchParams(window.location.search);
		// Remove legacy token fragments and error text immediately. Never accept
		// credentials from a URL; only the browser-bound server result can log in.
		window.history.replaceState(null, "", "/oidc-callback");
		if (query.has("error")) {
			setError(query.get("error"));
			return;
		}
		completeOidcLogin().catch(() => setError("SSO authentication failed. Please start again."));
	}, [completeOidcLogin]);

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
