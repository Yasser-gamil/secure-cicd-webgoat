# secure-cicd-webgoat

Secure CI/CD pipeline for OWASP WebGoat — Jenkins on Docker-in-Docker with linting, SAST, SCA, and DAST stages, plus pipeline and container hardening.

On the target application: OWASP WebGoat is a deliberately insecure application, maintained by OWASP as a security training tool. It is used here as the target-under-test: it guarantees the scanners have real findings to report, which is what makes the pipeline's output meaningful rather than a wall of green checkmarks. Dependency alerts on this repository are expected and intentional. WebGoat is never deployed anywhere reachable from an untrusted network.

What this repository is

A CI/CD pipeline built to demonstrate that security controls belong inside the delivery process rather than bolted on after it. The application is incidental; the pipeline and the reasoning behind its architecture are the deliverable.

Every architectural decision below is documented with its trade-off. Where a more secure option was rejected, the reason is stated.

Architecture
Ubuntu VM
Docker network: jenkins
mutual TLSDOCKER_HOST=tcp://docker:2376
builds & runs
builds & runs
scans
Jenkins controllerdocker CLI only:8080 published
docker:dind sidecar--privileged:2376 TLS, NOT published
WebGoat containerUID 10001, non-root
Scanner containersTrivy · ZAP · SAST

Only port 8080 is exposed to the host. The Docker daemon's API is reachable exclusively over the internal network, authenticated with client certificates.

Key design decisions
Docker-in-Docker, not a mounted host socket

The common approach to giving Jenkins container-build capability is to bind-mount the host's /var/run/docker.sock into the Jenkins container. It is faster to set up, and it is also equivalent to granting unrestricted root on the host: any pipeline step can mount / or launch a privileged container in the host's namespace.

This pipeline instead runs a docker:dind sidecar with its own daemon, which Jenkins reaches over an internal Docker network. The host's Docker socket is never exposed.

Trade-off, stated plainly: the sidecar itself requires --privileged. This relocates the privilege boundary rather than eliminating it. The gain is that a compromised pipeline step reaches a disposable daemon instead of the host. This is also Jenkins' own officially documented Docker installation pattern.

The daemon's API port is not published

An earlier iteration included --publish 2376:2376 on the sidecar. It was removed.

Jenkins resolves the daemon by network alias (tcp://docker:2376); container-to-container traffic on a user-defined bridge requires no published port. The flag was functionally inert while binding the API of a privileged, root-equivalent daemon to the VM's LAN address. TLS client-certificate authentication mitigated it but did not justify it — publishing a privileged control plane to the local network directly contradicts the reason DinD was chosen.

TLS on the daemon channel, not plaintext 2375

DOCKER_TLS_CERTDIR=/certs causes the sidecar to generate a CA and require client certificates. The control channel is mutually authenticated rather than anonymous. Jenkins mounts the certificate volume read-only.

Documented residual risk: shared trust domain

The Jenkins home volume is mounted into the dind sidecar, because the daemon — not Jenkins — resolves the paths used when pipeline steps bind-mount $WORKSPACE into scanner containers. Removing the mount breaks every scanner stage.

The consequence is stated rather than hidden: Jenkins' credential store resides within the trust domain of a privileged daemon that pipeline steps can drive. This is acceptable here because nothing untrusted executes — single repository, single maintainer, no builds from forked pull requests.

Production alternative: ephemeral per-build agents, or rootless image builds via Kaniko or Buildah, removing the privileged daemon entirely.

Minimal Jenkins controller

The Docker CLI is copied from the docker:cli image via a multi-stage build rather than installed with apt-get install docker.io. The apt package would pull containerd and runc into the controller — a complete container runtime that is never used. The controller receives a Docker client and nothing else.

Container hardening

Built as Dockerfile.secure, alongside the upstream Dockerfile so the two can be compared directly.

Control	Implementation
Non-root runtime	Fixed numeric UID 10001; verifiable with docker run --rm --entrypoint id webgoat:secure
No build toolchain in final image	Multi-stage build; Maven and the source tree stay in the discarded build stage
Reproducible build	Maven runs inside the image build, requiring no host toolchain — unlike upstream, which expects a pre-built JAR on the host
Image vulnerability scanning	Trivy stage in pipeline (planned)
Read-only root filesystem	Under evaluation — see below
Two findings worth recording

A slim JRE base image was evaluated and rejected. Several WebGoat lessons compile Java at runtime, so a JRE-only image breaks them — and breaks them silently, in a way that presents as a broken application rather than a missing compiler. The full JDK is retained deliberately. Reducing image size at the cost of application correctness is not a security improvement.

The upstream HEALTHCHECK was removed. It invokes curl, which means shipping an HTTP client inside the runtime image — a convenient exfiltration primitive for very little benefit. The pipeline must wait for application readiness before DAST regardless, so the readiness probe lives in the Jenkinsfile where it is explicit and auditable, rather than in image metadata.

WebGoat writes lesson state beneath -Duser.home=/home/webgoat. A blanket read-only root filesystem therefore breaks provisioning at startup; the intended approach is a read-only root with a writable tmpfs or volume mounted at that path specifically.

Pipeline stages
Stage	Tool	Status
Lint	Dockerfile + Groovy linting	Planned
SAST	Static analysis of WebGoat source	Planned
SCA	Trivy	Planned
Container scan	Trivy image scan	Planned
DAST	OWASP ZAP baseline scan	Planned
Threat model	STRIDE analysis — design artifact, not an automated stage	Planned

Two deliberate scoping decisions:

SCA uses Trivy rather than OWASP Dependency-Check. Dependency-Check's NVD synchronisation is slow and unreliable without an API key, making it a poor fit for a pipeline that must run predictably.
DAST is an unauthenticated baseline scan. A full authenticated crawl of WebGoat's lesson tree is out of scope; the baseline scan demonstrates the control and completes in a bounded time.
Readiness gating, not sleep

The DAST stage gates on WebGoat's actuator health endpoint rather than a fixed delay. If ZAP begins scanning before Spring Boot finishes initialising, it scans connection errors and passes with zero findings — a silent false negative, which is considerably worse than an outright failure.

Repository layout
Dockerfile.secure     # hardened multi-stage build (this project)
Dockerfile            # upstream WebGoat Dockerfile, retained for comparison
.dockerignore         # rewritten — see note below
Jenkinsfile           # pipeline definition (in progress)
jenkins-image/        # Jenkins controller image + pinned plugin set
docs/                 # threat model and architecture notes

Note on .dockerignore: upstream's excludes the entire source tree and re-includes only the pre-built JAR, which is correct for a build-on-host workflow and silently fatal for a build-in-image one. It reduced the build context to 8 kB and surfaced as ./mvnw: not found — an error three steps removed from its cause. Rewritten here to exclude only target, docs, and CI metadata. .git is retained intentionally, since Maven build-metadata plugins fail without it.

Reproducing this locally

Requires a Linux host with Docker, roughly 40 GB free disk, and 8 GB RAM.

bash
# 1. Network and volumes
docker network create jenkins
docker volume create jenkins-docker-certs
docker volume create jenkins-docker-data
docker volume create jenkins-data

# 2. Privileged dind sidecar — note: no published ports
docker run --name jenkins-docker --detach \
  --privileged --restart unless-stopped \
  --network jenkins --network-alias docker \
  --env DOCKER_TLS_CERTDIR=/certs \
  --volume jenkins-docker-certs:/certs/client \
  --volume jenkins-docker-data:/var/lib/docker \
  --volume jenkins-data:/var/jenkins_home \
  docker:dind --storage-driver overlay2

# 3. Build the controller image
cd jenkins-image && docker build -t jenkins-secure:local . && cd ..

# 4. Run the controller — only 8080 is published
docker run --name jenkins --detach \
  --restart unless-stopped \
  --network jenkins \
  --env DOCKER_HOST=tcp://docker:2376 \
  --env DOCKER_CERT_PATH=/certs/client \
  --env DOCKER_TLS_VERIFY=1 \
  --publish 8080:8080 \
  --volume jenkins-data:/var/jenkins_home \
  --volume jenkins-docker-certs:/certs/client:ro \
  jenkins-secure:local

# 5. Retrieve the initial admin password
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword

Verify the daemon connection before doing anything else — docker exec jenkins docker version must print both a Client: and a Server: section. The controller runs no daemon of its own, so a Server: block proves the network alias resolved, mutual TLS succeeded, and the API responded.

Licence and attribution

OWASP WebGoat is licensed under GPL-2.0 and remains the property of its maintainers. This repository contains pipeline and container configuration built around it.MDEOF

