# Inventory Service — Provider Plugins

This directory is a workspace for inventory provider plugins.
Each vendor has a top-level folder, with sub-folders for each
provider type (the tar-able, distributable unit).

## Structure

```
is-providers/
  vmware/
    vcenter/          ← tar this folder to create a distributable plugin
  microsoft/
    azure/            ← future
  cisco/
    nxos/             ← future
```

## Plugin folder contents

Each provider plugin folder is self-contained:

| File | Purpose |
|---|---|
| `manifest.yml` | Plugin identity, version, supported resource types, connection params |
| `provider.py` | The provider class (subclasses `BaseProvider`) |
| `requirements.txt` | Python pip dependencies |
| `requirements.yml` | Ansible collection dependencies |
| `bindep.txt` | System package dependencies |
| `meta/execution-environment.yml` | EE build metadata for ansible-builder |
| `meta/runtime.yml` | Runtime compatibility constraints |
| `pyproject.toml` | Package metadata and entry point declaration |

## Creating a distributable plugin

```bash
cd is-providers/vmware
tar czf vmware-vcenter-0.1.0.tar.gz vcenter/
```

The resulting tarball can be uploaded to the inventory service
via the provider-plugins API.

## Framework dependency

Plugins import from `inventory_providers.base`:

```python
from inventory_providers.base import BaseProvider, ProviderCredential, ResourceData
```

The `inventory_providers` package (base classes + registry) ships
with the inventory service itself. Plugin authors only need to
subclass `BaseProvider` — no Django dependency required.
