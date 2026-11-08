// Optional real-Nginx regression: node test/nginx-integration.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = await mkdtemp(path.join(tmpdir(), "npm-nginx-integration-"));
const name = `npm-security-${process.pid}`;
const dockerEnv = { ...process.env };
for (const key of ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"])
	delete dockerEnv[key];
const docker = (...args) =>
	execFileSync("docker", ["--host=unix:///var/run/docker.sock", ...args], { env: dockerEnv, encoding: "utf8" });
try {
	execFileSync(process.execPath, [path.join(here, "render-nginx-fixtures.mjs"), fixtures]);
	await mkdir(path.join(fixtures, "conf.d/include"), { recursive: true });
	docker(
		"run",
		"-d",
		"--name",
		name,
		"--mount",
		`type=bind,src=${fixtures},dst=/fixtures,readonly`,
		"--mount",
		`type=bind,src=${path.resolve(here, "../../docker/rootfs/etc/nginx/conf.d/include")},dst=/fixtures/conf.d/include,readonly`,
		"nginx:stable-alpine",
		"sh",
		"-c",
		'mkdir -p /data/nginx/custom /data/logs /data/access && nginx -t -c /fixtures/nginx.conf && nginx -c /fixtures/nginx.conf -g "daemon off;"',
	);
	// Bounded readiness loop; all requests stay on the container's loopback.
	for (let i = 0; i < 50; i++) {
		try {
			docker("exec", name, "sh", "-c", "nc -z 127.0.0.1 80");
			break;
		} catch (err) {
			if (i === 49) throw err;
			await new Promise((resolve) => setTimeout(resolve, 100));
		}
	}
	console.log(docker("exec", name, "nginx", "-t", "-c", "/fixtures/nginx.conf"));
	for (const host of ["authelia.test", "oauth2proxy.test", "root.test"]) {
		for (const uri of ["/", "/private", "/custom-root", "/style.css"]) {
			for (const authenticated of [false, true]) {
				const request = `GET ${uri} HTTP/1.1\r\nHost: ${host}\r\n${authenticated ? "Cookie: allowed=1\r\n" : ""}Connection: close\r\n\r\n`;
				const response = execFileSync(
					"docker",
					[
						"--host=unix:///var/run/docker.sock",
						"exec",
						name,
						"sh",
						"-c",
						'(printf "%s" "$1"; sleep 0.1) | nc -w 2 127.0.0.1 80',
						"sh",
						request,
					],
					{ input: request, env: dockerEnv, encoding: "utf8" },
				);
				assert.match(
					response,
					authenticated ? /^HTTP\/1.1 200/ : /^HTTP\/1.1 302/,
					`${host}${uri}, authenticated=${authenticated}: ${response}`,
				);
				if (authenticated) assert.ok(response.includes(`header=works host=${host}`), response);
			}
			console.log(`PASS ${host}${uri}: requires auth, forwards custom header after auth`);
		}
	}
	const hostFile = path.join(fixtures, "root.conf");
	const saved = await readFile(hostFile, "utf8");
	await writeFile(hostFile, saved.replace("proxy_read_timeout 60s;", "this_directive_does_not_exist on;"));
	assert.throws(() => docker("exec", name, "nginx", "-t", "-c", "/fixtures/nginx.conf"), /unknown directive/);
	console.log("PASS invalid custom directive rejected by nginx -t");
} finally {
	try {
		docker("rm", "-f", name);
	} catch {}
	await rm(fixtures, { recursive: true, force: true });
}
