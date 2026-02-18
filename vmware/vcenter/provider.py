"""VMware vSphere inventory collection provider.

Connects to a vCenter Server or standalone ESXi host via the vSphere
API (pyVmomi) and collects the full inventory hierarchy:

    Datacenters → Clusters → Hosts → VMs
                           → Resource Pools
                → Datastores

Resource type mapping (vSphere → normalized taxonomy):
    VirtualMachine           → virtual_machine
    HostSystem               → hypervisor_host
    ClusterComputeResource   → container_orchestration_platform
    Datastore                → block_storage
    ResourcePool             → auto_scaling_group

Requirements:
    pip install pyvmomi

Connection parameters (via ProviderCredential):
    hostname:       vCenter/ESXi hostname or IP
    port:           API port (default: 443)
    username:       vSphere username (e.g. administrator@vsphere.local)
    password:       vSphere password
    extra:
        validate_certs: Whether to verify TLS certificates (default: True)
        datacenter:     Optional — limit collection to a specific datacenter
"""
from __future__ import annotations

import atexit
import logging
import ssl
from typing import Iterator

from inventory_providers.base import BaseProvider, ProviderCredential, ResourceData

logger = logging.getLogger("inventory_providers.contrib.vmware_vsphere")

# Power state normalization
POWER_STATE_MAP = {
    "poweredOn": "running",
    "poweredOff": "stopped",
    "suspended": "suspended",
}


class VMwareVSphereProvider(BaseProvider):
    """Collect inventory from VMware vCenter / ESXi via pyVmomi."""

    vendor = "vmware"
    provider_type = "vcenter"
    display_name = "VMware vSphere (vCenter)"
    supported_resource_types = [
        "virtual_machine",
        "hypervisor_host",
        "container_orchestration_platform",
        "block_storage",
        "auto_scaling_group",
    ]

    def __init__(self, provider_model, credential: ProviderCredential):
        super().__init__(provider_model, credential)
        self._si = None  # pyVmomi ServiceInstance
        self._content = None

    # ── Connection ────────────────────────────────────────────────────

    def connect(self) -> None:
        """Connect to vCenter / ESXi using pyVmomi."""
        try:
            from pyVmomi import vim  # noqa: F401
            from pyVim.connect import SmartConnect, Disconnect
        except ImportError:
            raise ImportError(
                "pyvmomi is required for the VMware vSphere provider. "
                "Install with: pip install inventory-providers[vmware]"
            )

        validate_certs = self.credential.extra.get("validate_certs", self.credential.extra.get("verify_ssl", True))

        connect_kwargs = {
            "host": self.credential.hostname,
            "port": self.credential.port,
            "user": self.credential.username,
            "pwd": self.credential.password,
        }

        if not validate_certs:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            connect_kwargs["sslContext"] = ctx

        self.logger.info(
            "Connecting to vSphere: %s:%d as %s (validate_certs=%s)",
            self.credential.hostname,
            self.credential.port,
            self.credential.username,
            validate_certs,
        )

        self._si = SmartConnect(**connect_kwargs)
        atexit.register(Disconnect, self._si)
        self._content = self._si.RetrieveContent()

        self.logger.info(
            "Connected to vSphere: %s (API version %s)",
            self._content.about.fullName,
            self._content.about.apiVersion,
        )

    def disconnect(self) -> None:
        """Disconnect from vSphere."""
        if self._si is not None:
            try:
                from pyVim.connect import Disconnect
                Disconnect(self._si)
            except Exception:
                pass
            self._si = None
            self._content = None

    # ── Collection ────────────────────────────────────────────────────

    def collect(self) -> Iterator[ResourceData]:
        """
        Collect all inventory from vSphere.

        Yields resources in dependency order so relationships can be
        resolved in a single pass:
        1. Clusters
        2. Hosts
        3. Resource Pools
        4. Datastores
        5. VMs
        """
        from pyVmomi import vim

        content = self._content
        dc_filter = self.credential.extra.get("datacenter", "")

        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.Datacenter], True
        )
        datacenters = list(container.view)
        container.Destroy()

        if dc_filter:
            datacenters = [dc for dc in datacenters if dc.name == dc_filter]

        for dc in datacenters:
            dc_name = dc.name
            self.logger.info("Collecting datacenter: %s", dc_name)

            yield from self._collect_clusters(content, dc, dc_name)
            yield from self._collect_hosts(content, dc, dc_name)
            yield from self._collect_resource_pools(content, dc, dc_name)
            yield from self._collect_datastores(content, dc, dc_name)
            yield from self._collect_vms(content, dc, dc_name)

    # ── Per-type collectors ───────────────────────────────────────────

    def _collect_clusters(self, content, dc, dc_name: str) -> Iterator[ResourceData]:
        """Collect ClusterComputeResource objects."""
        from pyVmomi import vim

        container = content.viewManager.CreateContainerView(
            dc, [vim.ClusterComputeResource], True
        )
        for cluster in container.view:
            moid = cluster._moId
            config = cluster.configuration

            yield ResourceData(
                ems_ref=moid,
                resource_type_slug="container_orchestration_platform",
                name=cluster.name,
                canonical_id=f"vsphere:cluster:{moid}",
                vendor_identifiers={"moid": moid, "vsphere_type": "ClusterComputeResource"},
                vendor_type="vSphere Cluster",
                state="active",
                region=dc_name,
                properties={
                    "ha_enabled": bool(getattr(config.dasConfig, "enabled", False)),
                    "drs_enabled": bool(getattr(config.drsConfig, "enabled", False)),
                    "vsphere_type": "ClusterComputeResource",
                    "total_cpu_mhz": _safe_attr(cluster.summary, "totalCpu", 0),
                    "total_memory_bytes": _safe_attr(cluster.summary, "totalMemory", 0),
                    "num_hosts": _safe_attr(cluster.summary, "numHosts", 0),
                    "num_effective_hosts": _safe_attr(cluster.summary, "numEffectiveHosts", 0),
                },
            )
        container.Destroy()

    def _collect_hosts(self, content, dc, dc_name: str) -> Iterator[ResourceData]:
        """Collect HostSystem objects."""
        from pyVmomi import vim

        container = content.viewManager.CreateContainerView(
            dc, [vim.HostSystem], True
        )
        for host in container.view:
            moid = host._moId
            hw = host.hardware
            summary = host.summary
            config_summary = summary.config if summary else None
            hardware_summary = summary.hardware if summary else None

            # Cluster membership
            cluster_moid = ""
            cluster_name = ""
            if hasattr(host, "parent") and isinstance(host.parent, vim.ClusterComputeResource):
                cluster_moid = host.parent._moId
                cluster_name = host.parent.name

            # Hardware identity
            bios_uuid = ""
            serial_number = ""
            hw_model = ""
            hw_vendor = ""
            if hw and hw.systemInfo:
                bios_uuid = getattr(hw.systemInfo, "uuid", "") or ""
                serial_number = _first_id_value(hw.systemInfo.otherIdentifyingInfo, "ServiceTag") or ""
                hw_model = getattr(hw.systemInfo, "model", "") or ""
                hw_vendor = getattr(hw.systemInfo, "vendor", "") or ""

            cpu_count = 0
            memory_mb = 0
            if hardware_summary:
                cpu_count = getattr(hardware_summary, "numCpuCores", 0) or 0
                memory_mb = (getattr(hardware_summary, "memorySize", 0) or 0) // (1024 * 1024)

            ip = ""
            if config_summary:
                ip = getattr(config_summary, "name", "") or ""

            os_name = ""
            if config_summary and config_summary.product:
                os_name = f"{config_summary.product.name} {config_summary.product.version}"

            relationships = []
            if cluster_moid:
                relationships.append({
                    "target_ems_ref": cluster_moid,
                    "relationship_type": "part_of",
                })

            yield ResourceData(
                ems_ref=moid,
                resource_type_slug="hypervisor_host",
                name=host.name,
                canonical_id=bios_uuid,
                vendor_identifiers={
                    "moid": moid,
                    "smbios_uuid": bios_uuid,
                    "serial_number": serial_number,
                },
                vendor_type="ESXi Host",
                state="active" if _safe_attr(summary.runtime, "connectionState", "") == "connected" else "inactive",
                power_state="poweredOn" if _safe_attr(summary.runtime, "powerState", "") == "poweredOn" else "poweredOff",
                region=dc_name,
                cpu_count=cpu_count,
                memory_mb=memory_mb,
                ip_addresses=[ip] if ip else [],
                fqdn=host.name,
                os_type="hypervisor",
                os_name=os_name,
                properties={
                    "hardware_model": hw_model,
                    "hardware_vendor": hw_vendor,
                    "serial_number": serial_number,
                    "vsphere_type": "HostSystem",
                    "cluster": cluster_name,
                    "cluster_moid": cluster_moid,
                    "connection_state": _safe_attr(summary.runtime, "connectionState", ""),
                    "maintenance_mode": bool(_safe_attr(summary.runtime, "inMaintenanceMode", False)),
                },
                ansible_host=ip,
                ansible_connection="ssh",
                inventory_group="esxi_hosts",
                relationships=relationships,
            )
        container.Destroy()

    def _collect_resource_pools(self, content, dc, dc_name: str) -> Iterator[ResourceData]:
        """Collect ResourcePool objects."""
        from pyVmomi import vim

        container = content.viewManager.CreateContainerView(
            dc, [vim.ResourcePool], True
        )
        for pool in container.view:
            moid = pool._moId
            # Skip the implicit "Resources" root pool
            if pool.name == "Resources" and isinstance(pool.parent, vim.ClusterComputeResource):
                continue

            cluster_moid = ""
            cluster_name = ""
            parent = pool.parent
            while parent:
                if isinstance(parent, vim.ClusterComputeResource):
                    cluster_moid = parent._moId
                    cluster_name = parent.name
                    break
                parent = getattr(parent, "parent", None)

            cpu_limit = -1
            mem_limit = -1
            if pool.config:
                cpu_limit = getattr(pool.config.cpuAllocation, "limit", -1) or -1
                mem_limit = getattr(pool.config.memoryAllocation, "limit", -1) or -1

            relationships = []
            if cluster_moid:
                relationships.append({
                    "target_ems_ref": cluster_moid,
                    "relationship_type": "part_of",
                })

            yield ResourceData(
                ems_ref=moid,
                resource_type_slug="auto_scaling_group",
                name=pool.name,
                canonical_id=f"vsphere:respool:{moid}",
                vendor_identifiers={"moid": moid, "vsphere_type": "ResourcePool"},
                vendor_type="vSphere Resource Pool",
                state="active",
                region=dc_name,
                properties={
                    "cpu_limit_mhz": cpu_limit,
                    "memory_limit_mb": mem_limit,
                    "vsphere_type": "ResourcePool",
                    "cluster": cluster_name,
                },
                relationships=relationships,
            )
        container.Destroy()

    def _collect_datastores(self, content, dc, dc_name: str) -> Iterator[ResourceData]:
        """Collect Datastore objects."""
        from pyVmomi import vim

        container = content.viewManager.CreateContainerView(
            dc, [vim.Datastore], True
        )
        for ds in container.view:
            moid = ds._moId
            summary = ds.summary

            capacity_gb = 0
            free_gb = 0
            ds_type = ""
            if summary:
                capacity_gb = (getattr(summary, "capacity", 0) or 0) // (1024 ** 3)
                free_gb = (getattr(summary, "freeSpace", 0) or 0) // (1024 ** 3)
                ds_type = getattr(summary, "type", "") or ""

            provisioned_pct = 0.0
            if capacity_gb > 0:
                provisioned_pct = round((1 - free_gb / capacity_gb) * 100, 1)

            yield ResourceData(
                ems_ref=moid,
                resource_type_slug="block_storage",
                name=ds.name,
                canonical_id=f"vsphere:datastore:{moid}",
                vendor_identifiers={"moid": moid, "vsphere_type": "Datastore"},
                vendor_type="vSphere Datastore",
                state="active" if getattr(summary, "accessible", False) else "inactive",
                region=dc_name,
                disk_gb=capacity_gb,
                properties={
                    "datastore_type": ds_type.lower(),
                    "capacity_gb": capacity_gb,
                    "free_space_gb": free_gb,
                    "provisioned_pct": provisioned_pct,
                    "vsphere_type": "Datastore",
                    "url": getattr(summary, "url", "") or "",
                },
                metrics={"provisioned_pct": provisioned_pct},
            )
        container.Destroy()

    def _collect_vms(self, content, dc, dc_name: str) -> Iterator[ResourceData]:
        """Collect VirtualMachine objects."""
        from pyVmomi import vim

        container = content.viewManager.CreateContainerView(
            dc, [vim.VirtualMachine], True
        )
        for vm in container.view:
            moid = vm._moId
            config = vm.config
            summary = vm.summary
            guest = vm.guest
            runtime = vm.runtime

            # Identity
            bios_uuid = ""
            instance_uuid = ""
            vm_name = vm.name
            if config:
                bios_uuid = getattr(config, "uuid", "") or ""
                instance_uuid = getattr(config, "instanceUuid", "") or ""
                vm_name = config.name or vm.name

            # Compute
            cpu_count = 0
            memory_mb = 0
            disk_gb = 0
            if config and config.hardware:
                cpu_count = getattr(config.hardware, "numCPU", 0) or 0
                memory_mb = getattr(config.hardware, "memoryMB", 0) or 0
                for device in config.hardware.device:
                    if isinstance(device, vim.vm.device.VirtualDisk):
                        disk_gb += (getattr(device, "capacityInKB", 0) or 0) // (1024 * 1024)

            # Power state
            power_state_raw = _safe_attr(runtime, "powerState", "poweredOff")
            normalized_state = POWER_STATE_MAP.get(power_state_raw, "unknown")

            # Boot time
            boot_time = None
            if runtime:
                boot_time = getattr(runtime, "bootTime", None)

            # Guest info
            ip_addresses = []
            fqdn = ""
            os_name = ""
            os_type = ""
            mac_addresses = []

            if guest:
                primary_ip = getattr(guest, "ipAddress", "") or ""
                if primary_ip:
                    ip_addresses.append(primary_ip)

                if guest.net:
                    for nic in guest.net:
                        if nic.ipConfig and nic.ipConfig.ipAddress:
                            for ip_info in nic.ipConfig.ipAddress:
                                addr = ip_info.ipAddress
                                if addr and addr not in ip_addresses and ":" not in addr:
                                    ip_addresses.append(addr)
                        mac = getattr(nic, "macAddress", "")
                        if mac and mac not in mac_addresses:
                            mac_addresses.append(mac)

                fqdn = getattr(guest, "hostName", "") or ""
                os_name = getattr(guest, "guestFullName", "") or ""
                os_type = _classify_os(getattr(guest, "guestId", "") or "")

            if not os_name and config:
                os_name = getattr(config, "guestFullName", "") or ""
                os_type = os_type or _classify_os(getattr(config, "guestId", "") or "")

            # Host / cluster / datastore references
            host_moid = ""
            host_name = ""
            cluster_name = ""
            if runtime and runtime.host:
                host_moid = runtime.host._moId
                host_name = runtime.host.name
                if isinstance(runtime.host.parent, vim.ClusterComputeResource):
                    cluster_name = runtime.host.parent.name

            datastore_moid = ""
            datastore_name = ""
            if vm.datastore:
                datastore_moid = vm.datastore[0]._moId
                datastore_name = vm.datastore[0].name

            pool_moid = ""
            pool_name = ""
            if vm.resourcePool:
                pool_moid = vm.resourcePool._moId
                pool_name = vm.resourcePool.name

            # VMware Tools
            tools_status = ""
            tools_version = ""
            if guest:
                tools_status = getattr(guest, "toolsRunningStatus", "") or ""
                tools_version = getattr(guest, "toolsVersion", "") or ""

            hw_version = ""
            if config:
                hw_version = getattr(config, "version", "") or ""

            is_template = bool(getattr(config, "template", False)) if config else False

            # Ansible metadata
            ansible_host = ip_addresses[0] if ip_addresses else ""
            ansible_conn = ""
            if not is_template and normalized_state == "running":
                ansible_conn = "winrm" if os_type == "windows" else "ssh"

            provider_tags = {}
            if is_template:
                provider_tags["type"] = "template"

            # Relationships
            relationships = []
            if host_moid:
                relationships.append({"target_ems_ref": host_moid, "relationship_type": "runs_on"})
            if datastore_moid:
                relationships.append({"target_ems_ref": datastore_moid, "relationship_type": "attached_to"})
            if pool_moid and pool_name != "Resources":
                relationships.append({"target_ems_ref": pool_moid, "relationship_type": "member_of"})

            state = "inactive" if is_template else normalized_state

            # Metrics
            metrics = {}
            if summary and summary.quickStats and normalized_state == "running":
                qs = summary.quickStats
                cpu_usage = getattr(qs, "overallCpuUsage", 0) or 0
                if cpu_usage:
                    metrics["cpu_usage_mhz"] = cpu_usage
                mem_usage = getattr(qs, "guestMemoryUsage", 0) or 0
                if memory_mb > 0 and mem_usage > 0:
                    metrics["memory_usage_pct"] = round(mem_usage / memory_mb * 100, 1)
                metrics["memory_usage_mb"] = mem_usage

            yield ResourceData(
                ems_ref=moid,
                resource_type_slug="virtual_machine",
                name=vm_name,
                canonical_id=bios_uuid,
                vendor_identifiers={
                    "moid": moid,
                    "bios_uuid": bios_uuid,
                    "instance_uuid": instance_uuid,
                },
                vendor_type="vSphere VM",
                state=state,
                power_state=power_state_raw,
                boot_time=boot_time,
                region=dc_name,
                cpu_count=cpu_count,
                memory_mb=memory_mb,
                disk_gb=disk_gb,
                ip_addresses=ip_addresses,
                fqdn=fqdn,
                mac_addresses=mac_addresses,
                os_type=os_type,
                os_name=os_name,
                properties={
                    "vsphere_type": "VirtualMachine",
                    "cluster": cluster_name,
                    "host": host_name,
                    "resource_pool": pool_name,
                    "datastore": datastore_name,
                    "is_template": is_template,
                    "tools_status": tools_status,
                    "tools_version": tools_version,
                    "hardware_version": hw_version,
                    "linked_clone": _is_linked_clone(config),
                },
                provider_tags=provider_tags,
                ansible_host=ansible_host,
                ansible_connection=ansible_conn,
                inventory_group=_suggest_inventory_group(os_type, is_template),
                relationships=relationships,
                metrics=metrics,
            )
        container.Destroy()


# ── Helpers ───────────────────────────────────────────────────────────


def _safe_attr(obj, attr: str, default=None):
    """Safely get an attribute from a vSphere managed object."""
    if obj is None:
        return default
    return getattr(obj, attr, default)


def _first_id_value(identifying_info, id_type: str) -> str:
    """Extract a value from HostSystemIdentificationInfo by type."""
    if not identifying_info:
        return ""
    for info in identifying_info:
        if hasattr(info, "identifierType") and info.identifierType:
            if getattr(info.identifierType, "key", "") == id_type:
                return getattr(info, "identifierValue", "") or ""
    return ""


def _classify_os(guest_id: str) -> str:
    """Classify a vSphere guestId into a normalized os_type."""
    if not guest_id:
        return ""
    gid = guest_id.lower()
    if "win" in gid:
        return "windows"
    if any(x in gid for x in ("rhel", "centos", "ubuntu", "debian", "sles",
                                "fedora", "oracle", "linux", "alma", "rocky")):
        return "linux"
    if "freebsd" in gid:
        return "bsd"
    if "darwin" in gid or "mac" in gid:
        return "macos"
    return "other"


def _is_linked_clone(config) -> bool:
    """Check if a VM is a linked clone (has delta disk backing)."""
    if not config or not config.hardware:
        return False
    try:
        from pyVmomi import vim
        for device in config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualDisk):
                backing = device.backing
                if hasattr(backing, "parent") and backing.parent is not None:
                    return True
    except Exception:
        pass
    return False


def _suggest_inventory_group(os_type: str, is_template: bool) -> str:
    """Suggest an Ansible inventory group based on OS."""
    if is_template:
        return ""
    if os_type == "windows":
        return "windows"
    if os_type == "linux":
        return "linux"
    return ""
