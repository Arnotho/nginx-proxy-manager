// Run with Node from backend/: node test/render-nginx-fixtures.mjs <output-dir>
// Produces real NPM host templates; tests run them with the official nginx image.
import fs from "node:fs/promises";
import path from "node:path";
import utils from "../lib/utils.js";

const output = path.resolve(process.argv[2]);
await fs.mkdir(output, { recursive: true });
const engine = utils.getRenderEngine();
const base = {
	enabled: true,
	forward_scheme: "http",
	forward_host: "127.0.0.1",
	forward_port: 9002,
	ipv6: false,
	use_default_location: true,
	certificate_id: 0,
	access_list_id: 1,
	access_list: { id: 1, items: [], clients: [{ directive: "allow", address: "127.0.0.1" }], satisfy_any: true },
	caching_enabled: true,
	advanced_config: "",
	proxy_config: 'proxy_set_header X-Example "works";\nproxy_read_timeout 60s;',
	authelia_upstream_url: "http://127.0.0.1:9001/api/authz/auth-request",
	oauth2proxy_upstream_url: "http://127.0.0.1:9001",
};
const locationTemplate = await fs.readFile(new URL("../templates/_location.conf", import.meta.url), "utf8");
const hostTemplate = await fs.readFile(new URL("../templates/proxy_host.conf", import.meta.url), "utf8");
let id = 1;
for (const auth_type of ["authelia", "oauth2proxy"]) {
	const host = { ...base, auth_type, id: id++, domain_names: [`${auth_type}.test`] };
	let locations = "";
	for (const p of ["/private", "/custom-root"])
		locations += await engine.parseAndRender(locationTemplate, { ...host, path: p });
	const config = await engine.parseAndRender(hostTemplate, { ...host, locations });
	await fs.writeFile(path.join(output, `${auth_type}.conf`), config);
}
// OAuth2Proxy protects a custom '/' that replaces the generated default location.
const rootHost = {
	...base,
	auth_type: "oauth2proxy",
	id: id++,
	domain_names: ["root.test"],
	use_default_location: false,
};
const rootLocation = await engine.parseAndRender(locationTemplate, { ...rootHost, path: "/" });
await fs.writeFile(
	path.join(output, "root.conf"),
	await engine.parseAndRender(hostTemplate, { ...rootHost, locations: rootLocation }),
);
const nginxConf = `events {}
http {
  log_format proxy '$remote_addr $status';
  map $http_host $forward_host { default $http_host; }
  map $scheme $x_forwarded_scheme { default $scheme; }
  map $scheme $x_forwarded_proto { default $scheme; }
  server {
    listen 9001;
    location = /api/authz/auth-request {
      if ($http_cookie = "allowed=1") { return 200; }
      add_header Location https://login.test/login always;
      return 401;
    }
    location = /oauth2/auth {
      if ($http_cookie = "allowed=1") { return 202; }
      return 401;
    }
    location = /oauth2/sign_in { return 302 /login; }
  }
  server {
    listen 9002;
    location / { return 200 "header=$http_x_example host=$http_host\\n"; }
  }
  include /fixtures/authelia.conf;
  include /fixtures/oauth2proxy.conf;
  include /fixtures/root.conf;
}
`;
await fs.writeFile(path.join(output, "nginx.conf"), nginxConf);
