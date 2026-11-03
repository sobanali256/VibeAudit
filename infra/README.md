# infra

Provisioning scripts for the two Vultr VMs, run over SSH:

- `cp/`: VM 1, the control plane. Caddy (HTTPS), Postgres, web app, worker, mitmproxy egress proxy and host firewall for VPC traffic.
- `sbx/`: VM 2, the sandbox host. Docker + gVisor (`runsc`), `DOCKER-USER` egress lock to the VM 1 proxy only, and sshd restricted to VM 1 over the VPC.
