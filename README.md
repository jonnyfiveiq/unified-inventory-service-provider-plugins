# Inventory Service — Provider Plugins

Provider plugins are the collection layer for the
[Inventory Service](https://github.com/jonnyfiveiq/unified-inventory-service).
Each plugin connects to an external infrastructure platform (vCenter, AWS,
Azure, etc.), discovers the resources it manages, and yields them in a
normalised format that the inventory service stores, tracks and exposes
through its REST API.

## How providers and plugins fit together

The inventory service has two related but distinct concepts:

**Provider** — a model record in the inventory service database that
represents a specific connection to an external system. It carries the
endpoint URL, credentials, region/datacenter scope, and an
`organisation` owner. Providers are managed through the CRUD API at
`/api/inventory/v1/providers/`.

**Provider plugin** — a Python package in this repository that contains
the code to actually connect to that type of system and collect
inventory. Plugins are uploaded to the running inventory service, which
hot-loads them into its plugin registry at runtime — no restart needed.

The link between the two is a `vendor` + `provider_type` key pair.
When you trigger a collection run on a Provider, the inventory service
looks up the matching plugin in its registry by that key and
instantiates it with the resolved credentials.

```
Provider record (DB)                 Plugin (this repo)
─────────────────────                ─────────────────────
vendor = "vmware"        ◄──────►   vendor = "vmware"
provider_type = "vcenter"            provider_type = "vcenter"
endpoint = "https://..."             class VMwareVSphereProvider(BaseProvider)
connection_config = {...}            def connect / collect / disconnect
```

A provider record without a matching plugin will fail at collection
time. A plugin without a matching provider record simply sits idle in
the registry until one is created.

## Repository structure

```
is-providers/
├── vmware/
│   └── vcenter/        ← VMware vSphere (vCenter) plugin  [vmware:vcenter]
├── amazon/
│   └── aws/            ← Amazon Web Services plugin        [aws:aws]
├── microsoft/          ← (future)
│   └── azure/
└── cisco/              ← (future)
    └── nxos/
```

Each leaf folder (e.g. `vmware/vcenter/`) is a self-contained,
distributable plugin. The top-level folder is the company/namespace,
the sub-folder is the platform or system.

## Plugin contents

Every plugin folder contains the same set of files:

| File | Purpose |
|---|---|
| `manifest.yml` | Plugin identity, version, supported resource types, connection parameters |
| `provider.py` | The provider class — subclasses `BaseProvider`, implements `connect()`, `collect()`, `disconnect()` |
| `__init__.py` | Package init — exports the provider class |
| `pyproject.toml` | Package metadata with `inventory_providers` entry point |
| `requirements.txt` | Python pip dependencies |
| `requirements.yml` | Ansible collection dependencies |
| `bindep.txt` | System (OS) package dependencies |
| `meta/execution-environment.yml` | EE build metadata for ansible-builder |
| `meta/runtime.yml` | Runtime compatibility constraints |
| `install.sh` | Upload script for deploying the plugin to a running aap-dev cluster |

## Installing a plugin

Plugins are uploaded to the inventory service via its REST API. The
service validates the manifest, installs the Python package, and
hot-loads the provider class into the in-memory registry — all without
a restart.

### Using install.sh (recommended)

Each plugin includes an `install.sh` script that automates the full
upload workflow. From the plugin directory:

```bash
cd is-providers/vmware/vcenter
./install.sh
```

The script will:

1. Auto-detect your `aap-dev` checkout, kubeconfig, and admin password
2. Package the plugin directory into a tarball (excluding build artifacts)
3. Upload it via `POST /api/inventory/v1/provider-plugins/upload/`
4. Display the registered plugin key, class path, and supported resource types

If the plugin is already installed, use `--force` to overwrite:

```bash
./install.sh --force
```

The script supports environment variable overrides for non-standard setups:

| Variable | Default | Description |
|---|---|---|
| `AAP_DEV_ROOT` | Auto-detected | Path to aap-dev checkout |
| `IS_API_URL` | Auto-detected | Full inventory API base URL |
| `IS_USERNAME` | `admin` | API username |
| `IS_PASSWORD` | Auto-detected from cluster | API password |
| `AAP_NAMESPACE` | `aap26` | Kubernetes namespace |

### Manual upload via curl

```bash
# Package the plugin
cd is-providers/vmware/vcenter
tar czf /tmp/plugin.tar.gz --exclude='install.sh' --exclude='__pycache__' .

# Upload
curl -X POST \
  -u admin:$PASS \
  -F "plugin=@/tmp/plugin.tar.gz;type=application/gzip" \
  http://localhost:44926/api/inventory/v1/provider-plugins/upload/
```

### Plugin management API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/provider-plugins/` | List all installed plugins |
| `GET` | `/provider-plugins/{vendor:type}/` | Plugin detail and dependencies |
| `POST` | `/provider-plugins/upload/` | Upload a new plugin tarball |
| `POST` | `/provider-plugins/upload/?force=true` | Overwrite an existing plugin |
| `DELETE` | `/provider-plugins/{vendor:type}/` | Remove an installed plugin |
| `POST` | `/provider-plugins/{vendor:type}/test/` | Test connectivity for configured providers |
| `POST` | `/provider-plugins/refresh/` | Re-scan the plugin registry |

## Creating a provider instance

Once a plugin is uploaded, create a Provider record to connect to a
specific instance of that platform:

```bash
curl -X POST \
  -u admin:$PASS \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Production vCenter",
    "infrastructure": "private_cloud",
    "vendor": "vmware",
    "provider_type": "vcenter",
    "endpoint": "vcsa01.lab.local",
    "organization": 1,
    "connection_config": {
      "username": "administrator@vsphere.local",
      "password": "secret",
      "port": 443,
      "verify_ssl": false
    }
  }' \
  http://localhost:44926/api/inventory/v1/providers/
```

For AWS:

```bash
curl -X POST \
  -u admin:$PASS \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "AWS Production - us-east-1",
    "infrastructure": "public_cloud",
    "vendor": "aws",
    "provider_type": "aws",
    "endpoint": "https://ec2.us-east-1.amazonaws.com",
    "organization": 1,
    "connection_config": {
      "username": "AKIAIOSFODNN7EXAMPLE",
      "password": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "region": "us-east-1"
    }
  }' \
  http://localhost:44926/api/inventory/v1/providers/
```

The `vendor` and `provider_type` fields must match the plugin's
registry key exactly.

## Triggering a collection

```bash
curl -X POST \
  -u admin:$PASS \
  -H 'Content-Type: application/json' \
  http://localhost:44926/api/inventory/v1/providers/{id}/collect/
```

This creates a CollectionRun, dispatches an async task, and returns
`202 Accepted`. The plugin's `connect()` → `collect()` → `disconnect()`
cycle runs in the background. Discovered resources appear at
`/api/inventory/v1/resources/`.

## Available plugins

### vmware/vcenter — VMware vSphere

Connects to vCenter Server or standalone ESXi hosts via pyVmomi.
Registry key: `vmware:vcenter`

| Resource type | vSphere object |
|---|---|
| `virtual_machine` | VirtualMachine |
| `hypervisor_host` | HostSystem (ESXi) |
| `container_orchestration_platform` | ClusterComputeResource |
| `block_storage` | Datastore |
| `auto_scaling_group` | ResourcePool |

### amazon/aws — Amazon Web Services

Connects to AWS accounts via boto3 with multi-region scanning and
STS AssumeRole support. Registry key: `aws:aws`

| Resource type | AWS service |
|---|---|
| `virtual_machine` | EC2 instances |
| `vpc` | VPCs |
| `security_group` | Security groups |
| `block_storage` | EBS volumes |
| `object_storage` | S3 buckets |
| `relational_db` | RDS instances |
| `load_balancer` | ALB / NLB (ELBv2) |
| `serverless_function` | Lambda functions |
| `container_orchestration_platform` | EKS clusters |
| `auto_scaling_group` | Auto Scaling groups |

## Writing a new plugin

1. Create a new folder: `{company}/{platform}/`
2. Copy the file structure from an existing plugin
3. Subclass `BaseProvider` and implement `connect()`, `collect()`, `disconnect()`
4. `collect()` yields `ResourceData` objects — one per discovered resource
5. Use `resource_type_slug` values from the inventory service taxonomy
6. Set `vendor` and `provider_type` class attributes to match your `manifest.yml`
7. Run `./install.sh` to upload and test

```python
from inventory_providers.base import BaseProvider, ProviderCredential, ResourceData

class MyProvider(BaseProvider):
    vendor = "myvendor"
    provider_type = "myplatform"
    supported_resource_types = ["virtual_machine"]

    def connect(self):
        self.client = SomeSDK(host=self.credential.hostname,
                              token=self.credential.password)

    def disconnect(self):
        self.client.close()

    def collect(self):
        for vm in self.client.list_vms():
            yield ResourceData(
                ems_ref=vm.id,
                resource_type_slug="virtual_machine",
                name=vm.name,
                state="running" if vm.active else "stopped",
            )
```

The `inventory_providers` base package ships with the inventory
service — no Django dependency is needed to develop or test plugins.

## License

Apache License 2.0
