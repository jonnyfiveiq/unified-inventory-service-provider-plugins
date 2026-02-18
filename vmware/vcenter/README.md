# VMware vSphere (vCenter) Provider Plugin

Collects inventory from a VMware vCenter Server or standalone ESXi host using
the [pyVmomi](https://github.com/vmware/pyvmomi) SDK.

## Resource types collected

| Resource type | vSphere object | Key fields |
|---|---|---|
| `hypervisor_host` | HostSystem | CPU, memory, connection state, maintenance mode, SMBIOS UUID, serial |
| `virtual_machine` | VirtualMachine | CPU, memory, disk, IPs, MACs, guest OS, VMware Tools, template flag, linked clone |
| `block_storage` | Datastore | Capacity, free space, type (VMFS/NFS), provisioned %, URL |
| `auto_scaling_group` | ResourcePool | CPU/memory limits |
| `container_orchestration_platform` | ClusterComputeResource | DRS, HA, host count |

## Prerequisites

- vCenter 6.7+ or standalone ESXi 6.7+
- A user with at least **Read-only** role at the Datacenter level
- Network connectivity from the inventory-service pod to the vCenter on port 443

## Install

```bash
cd is-providers/vmware/vcenter
./install.sh --force
```

The install script packages the plugin, uploads it to the inventory service
API, and installs the `pyvmomi` pip dependency into the shared plugins volume.
No pod restart required.

## Create a provider

```bash
curl -s -X POST -u admin:$PASS 
  -H "Content-Type: application/json" 
  http://localhost:44926/api/inventory/v1/providers/ 
  -d '{
    "name": "Home Lab vCenter",
    "vendor": "vmware",
    "provider_type": "vcenter",
    "infrastructure": "private_cloud",
    "organization": 1,
    "endpoint": "192.168.0.195",
    "connection_config": {
      "username": "administrator@vsphere.local",
      "password": "secret",
      "port": 443,
      "verify_ssl": false
    }
  }'
```

## Connection config fields

| Field | Type | Default | Description |
|---|---|---|---|
| `username` | string | required | vCenter SSO user or ESXi local user |
| `password` | string | required | Password |
| `port` | int | `443` | vCenter SDK port |
| `verify_ssl` | bool | `true` | Set `false` for self-signed certificates |

## Trigger a collection

```bash
curl -s -X POST -u admin:$PASS \
  http://localhost:44926/api/inventory/v1/providers/{id}/collect/
```

## Example collected resources

A single collection against a home lab vCenter with 2 ESXi hosts returned
23 resources in under 1 second:

### Hypervisor host

```json
{
  "resource_type_slug": "hypervisor_host",
  "name": "192.168.0.144",
  "ems_ref": "host-10",
  "canonical_id": "8f6139c4-1f7c-11e7-bfbd-6ff82c1f1500",
  "vendor_type": "ESXi Host",
  "state": "active",
  "power_state": "poweredOn",
  "region": "Datacenter",
  "cpu_count": 4,
  "memory_mb": 32656,
  "os_name": "VMware ESXi 7.0.3",
  "ip_addresses": ["192.168.0.144"],
  "vendor_identifiers": {
    "moid": "host-10",
    "smbios_uuid": "8f6139c4-1f7c-11e7-bfbd-6ff82c1f1500",
    "serial_number": "S4BS6130"
  },
  "properties": {
    "hardware_vendor": "LENOVO",
    "hardware_model": "10FLS1W20R",
    "connection_state": "connected",
    "maintenance_mode": false
  },
  "ansible_host": "192.168.0.144",
  "ansible_connection": "ssh",
  "inventory_group": "esxi_hosts"
}
```

### Virtual machine

```json
{
  "resource_type_slug": "virtual_machine",
  "name": "VMware vCenter Server",
  "ems_ref": "vm-13",
  "canonical_id": "564d507d-f062-9948-d5a7-8ec278f59cf5",
  "vendor_type": "vSphere VM",
  "state": "running",
  "power_state": "poweredOn",
  "region": "Datacenter",
  "cpu_count": 2,
  "memory_mb": 12288,
  "disk_gb": 584,
  "os_name": "VMware Photon OS (64-bit)",
  "ip_addresses": ["192.168.0.195"],
  "fqdn": "vsphere.local",
  "mac_addresses": ["00:0c:29:f5:9c:f5"],
  "boot_time": "2026-02-17T22:12:44Z",
  "vendor_identifiers": {
    "moid": "vm-13",
    "bios_uuid": "564d507d-f062-9948-d5a7-8ec278f59cf5",
    "instance_uuid": "5276a0e4-35c2-5ce6-5199-31dcfe7699a9"
  },
  "properties": {
    "host": "192.168.0.144",
    "datastore": "datastore1",
    "is_template": false,
    "linked_clone": false,
    "tools_status": "guestToolsRunning",
    "tools_version": "12352",
    "hardware_version": "vmx-10"
  },
  "ansible_host": "192.168.0.195",
  "ansible_connection": "ssh",
  "inventory_group": ""
}
```

### Datastore (block storage)

```json
{
  "resource_type_slug": "block_storage",
  "name": "datastore1",
  "ems_ref": "datastore-11",
  "vendor_type": "vSphere Datastore",
  "state": "active",
  "disk_gb": 803,
  "properties": {
    "capacity_gb": 803,
    "free_space_gb": 335,
    "datastore_type": "vmfs",
    "provisioned_pct": 58.3,
    "url": "ds:///vmfs/volumes/68165de6-e3c8e36f-056f-002324e31e3d/"
  }
}
```

### Resource pool (auto-scaling group)

```json
{
  "resource_type_slug": "auto_scaling_group",
  "name": "Resources",
  "ems_ref": "resgroup-9",
  "vendor_type": "vSphere Resource Pool",
  "state": "active",
  "properties": {
    "cpu_limit_mhz": 7806,
    "memory_limit_mb": 27631
  }
}
```
