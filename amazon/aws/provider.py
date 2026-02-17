"""AWS inventory collection provider.

Connects to an AWS account via boto3 and collects infrastructure
inventory across one or more regions:

    EC2 Instances        -> virtual_machine
    VPCs                 -> vpc
    Security Groups      -> security_group
    EBS Volumes          -> block_storage
    S3 Buckets           -> object_storage
    RDS Instances        -> relational_db
    ELB / ALB / NLB      -> load_balancer
    Lambda Functions     -> serverless_function
    EKS Clusters         -> container_orchestration_platform
    Auto Scaling Groups  -> auto_scaling_group

Requirements:
    pip install boto3
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

from inventory_providers.base import BaseProvider, ProviderCredential, ResourceData

logger = logging.getLogger("inventory_providers.contrib.amazon_aws")

EC2_STATE_MAP = {
    "running": "running",
    "stopped": "stopped",
    "terminated": "decommissioned",
    "pending": "provisioning",
    "shutting-down": "stopping",
    "stopping": "stopping",
}

RDS_STATE_MAP = {
    "available": "running",
    "stopped": "stopped",
    "starting": "provisioning",
    "stopping": "stopping",
    "creating": "provisioning",
    "deleting": "decommissioned",
    "failed": "error",
    "maintenance": "maintenance",
    "modifying": "running",
    "rebooting": "running",
    "backing-up": "running",
}


class AWSCloudProvider(BaseProvider):
    """Collect inventory from AWS via boto3."""

    vendor = "aws"
    provider_type = "aws"
    display_name = "Amazon Web Services"
    supported_resource_types = [
        "virtual_machine",
        "vpc",
        "security_group",
        "block_storage",
        "object_storage",
        "relational_db",
        "load_balancer",
        "serverless_function",
        "container_orchestration_platform",
        "auto_scaling_group",
    ]

    def __init__(self, provider_model, credential: ProviderCredential):
        super().__init__(provider_model, credential)
        self._session = None
        self._regions: list[str] = []
        self._account_id: str = ""

    def connect(self) -> None:
        """Create a boto3 session, optionally assuming an IAM role."""
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "boto3 is required for the AWS provider. "
                "Install with: pip install inventory-providers[aws]"
            )

        extra = self.credential.extra
        session_kwargs: dict[str, Any] = {}
        if self.credential.username:
            session_kwargs["aws_access_key_id"] = self.credential.username
        if self.credential.password:
            session_kwargs["aws_secret_access_key"] = self.credential.password
        if extra.get("session_token"):
            session_kwargs["aws_session_token"] = extra["session_token"]

        primary_region = extra.get("region", "us-east-1")
        session_kwargs["region_name"] = primary_region
        self._session = boto3.Session(**session_kwargs)

        assume_role_arn = extra.get("assume_role_arn", "")
        if assume_role_arn:
            sts = self._session.client("sts")
            assume_kwargs: dict[str, str] = {
                "RoleArn": assume_role_arn,
                "RoleSessionName": "inventory-service-collection",
            }
            external_id = extra.get("external_id", "")
            if external_id:
                assume_kwargs["ExternalId"] = external_id
            self.logger.info("Assuming IAM role: %s", assume_role_arn)
            creds = sts.assume_role(**assume_kwargs)["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=primary_region,
            )

        sts = self._session.client("sts")
        self._account_id = sts.get_caller_identity()["Account"]

        regions = extra.get("regions", [])
        if regions:
            self._regions = regions
        elif extra.get("region"):
            self._regions = [extra["region"]]
        else:
            ec2 = self._session.client("ec2", region_name=primary_region)
            self._regions = [
                r["RegionName"]
                for r in ec2.describe_regions(
                    Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
                )["Regions"]
            ]

        self.logger.info(
            "Connected to AWS account %s - scanning %d region(s): %s",
            self._account_id, len(self._regions), ", ".join(self._regions),
        )

    def disconnect(self) -> None:
        self._session = None

    def collect(self) -> Iterator[ResourceData]:
        yield from self._collect_s3_buckets()
        for region in self._regions:
            self.logger.info("Collecting region: %s", region)
            yield from self._collect_vpcs(region)
            yield from self._collect_security_groups(region)
            yield from self._collect_ec2_instances(region)
            yield from self._collect_ebs_volumes(region)
            yield from self._collect_rds_instances(region)
            yield from self._collect_load_balancers(region)
            yield from self._collect_lambda_functions(region)
            yield from self._collect_eks_clusters(region)
            yield from self._collect_auto_scaling_groups(region)

    def _collect_ec2_instances(self, region: str) -> Iterator[ResourceData]:
        """Collect EC2 instances in a region."""
        ec2 = self._session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    instance_id = inst["InstanceId"]
                    state_name = inst["State"]["Name"]
                    normalized_state = EC2_STATE_MAP.get(state_name, "unknown")
                    if normalized_state == "decommissioned":
                        continue

                    name = _get_tag(inst, "Name") or instance_id
                    ip_addresses = []
                    if inst.get("PrivateIpAddress"):
                        ip_addresses.append(inst["PrivateIpAddress"])
                    if inst.get("PublicIpAddress"):
                        ip_addresses.append(inst["PublicIpAddress"])

                    mac_addresses = []
                    for nic in inst.get("NetworkInterfaces", []):
                        mac = nic.get("MacAddress", "")
                        if mac and mac not in mac_addresses:
                            mac_addresses.append(mac)

                    platform = inst.get("PlatformDetails", "") or inst.get("Platform", "") or ""
                    os_type = "windows" if "windows" in platform.lower() else "linux"
                    vpc_id = inst.get("VpcId", "")
                    az = inst.get("Placement", {}).get("AvailabilityZone", "")
                    sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                    launch_time = inst.get("LaunchTime")

                    cpu_count = None
                    if inst.get("CpuOptions"):
                        cpu_count = (inst["CpuOptions"].get("CoreCount", 0)
                                     * inst["CpuOptions"].get("ThreadsPerCore", 1))

                    relationships = []
                    if vpc_id:
                        relationships.append({"target_ems_ref": vpc_id, "relationship_type": "member_of"})
                    for sg_id in sg_ids:
                        relationships.append({"target_ems_ref": sg_id, "relationship_type": "attached_to"})

                    yield ResourceData(
                        ems_ref=instance_id,
                        resource_type_slug="virtual_machine",
                        name=name,
                        canonical_id=instance_id,
                        vendor_identifiers={
                            "instance_id": instance_id,
                            "image_id": inst.get("ImageId", ""),
                            "account_id": self._account_id,
                        },
                        vendor_type="EC2 Instance",
                        state=normalized_state,
                        power_state=state_name,
                        boot_time=launch_time,
                        region=region,
                        availability_zone=az,
                        cloud_tenant=self._account_id,
                        flavor=inst.get("InstanceType", ""),
                        cpu_count=cpu_count,
                        ip_addresses=ip_addresses,
                        fqdn=inst.get("PrivateDnsName", ""),
                        mac_addresses=mac_addresses,
                        os_type=os_type,
                        os_name=platform,
                        properties={
                            "instance_type": inst.get("InstanceType", ""),
                            "image_id": inst.get("ImageId", ""),
                            "vpc_id": vpc_id,
                            "subnet_id": inst.get("SubnetId", ""),
                            "key_name": inst.get("KeyName", ""),
                            "architecture": inst.get("Architecture", ""),
                            "hypervisor": inst.get("Hypervisor", ""),
                            "virtualization_type": inst.get("VirtualizationType", ""),
                            "ebs_optimized": inst.get("EbsOptimized", False),
                            "ena_support": inst.get("EnaSupport", False),
                            "monitoring_state": inst.get("Monitoring", {}).get("State", ""),
                            "security_groups": sg_ids,
                            "iam_instance_profile": inst.get("IamInstanceProfile", {}).get("Arn", ""),
                        },
                        provider_tags=_tags_to_dict(inst),
                        ansible_host=ip_addresses[0] if ip_addresses else "",
                        ansible_connection="winrm" if os_type == "windows" else "ssh",
                        inventory_group=_suggest_inventory_group(os_type, _tags_to_dict(inst)),
                        ems_created_on=launch_time,
                        relationships=relationships,
                    )

    def _collect_vpcs(self, region: str) -> Iterator[ResourceData]:
        """Collect VPCs in a region."""
        ec2 = self._session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            for vpc in page["Vpcs"]:
                vpc_id = vpc["VpcId"]
                name = _get_tag(vpc, "Name") or vpc_id
                yield ResourceData(
                    ems_ref=vpc_id,
                    resource_type_slug="vpc",
                    name=name,
                    canonical_id=vpc_id,
                    vendor_identifiers={"vpc_id": vpc_id, "account_id": self._account_id},
                    vendor_type="VPC",
                    state="active" if vpc["State"] == "available" else "provisioning",
                    region=region,
                    cloud_tenant=self._account_id,
                    properties={
                        "cidr_block": vpc.get("CidrBlock", ""),
                        "is_default": vpc.get("IsDefault", False),
                        "dhcp_options_id": vpc.get("DhcpOptionsId", ""),
                        "instance_tenancy": vpc.get("InstanceTenancy", ""),
                    },
                    provider_tags=_tags_to_dict(vpc),
                )

    def _collect_security_groups(self, region: str) -> Iterator[ResourceData]:
        """Collect security groups in a region."""
        ec2 = self._session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                vpc_id = sg.get("VpcId", "")
                relationships = []
                if vpc_id:
                    relationships.append({"target_ems_ref": vpc_id, "relationship_type": "member_of"})
                yield ResourceData(
                    ems_ref=sg_id,
                    resource_type_slug="security_group",
                    name=sg.get("GroupName", sg_id),
                    description=sg.get("Description", ""),
                    canonical_id=sg_id,
                    vendor_identifiers={"group_id": sg_id, "account_id": self._account_id},
                    vendor_type="Security Group",
                    state="active",
                    region=region,
                    cloud_tenant=self._account_id,
                    properties={
                        "vpc_id": vpc_id,
                        "ingress_rule_count": len(sg.get("IpPermissions", [])),
                        "egress_rule_count": len(sg.get("IpPermissionsEgress", [])),
                    },
                    provider_tags=_tags_to_dict(sg),
                    relationships=relationships,
                )

    def _collect_ebs_volumes(self, region: str) -> Iterator[ResourceData]:
        """Collect EBS volumes in a region."""
        ec2 = self._session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_volumes")
        state_map = {"available": "active", "in-use": "active",
                     "creating": "provisioning", "deleting": "decommissioned", "error": "error"}
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                volume_id = vol["VolumeId"]
                name = _get_tag(vol, "Name") or volume_id
                attachments = vol.get("Attachments", [])
                attached_instance = attachments[0].get("InstanceId", "") if attachments else ""
                device_name = attachments[0].get("Device", "") if attachments else ""
                relationships = []
                if attached_instance:
                    relationships.append({"target_ems_ref": attached_instance, "relationship_type": "attached_to"})
                yield ResourceData(
                    ems_ref=volume_id,
                    resource_type_slug="block_storage",
                    name=name,
                    canonical_id=volume_id,
                    vendor_identifiers={"volume_id": volume_id, "account_id": self._account_id},
                    vendor_type="EBS Volume",
                    state=state_map.get(vol.get("State", ""), "unknown"),
                    region=region,
                    availability_zone=vol.get("AvailabilityZone", ""),
                    cloud_tenant=self._account_id,
                    disk_gb=vol.get("Size", 0),
                    properties={
                        "volume_type": vol.get("VolumeType", ""),
                        "iops": vol.get("Iops", 0),
                        "throughput_mbps": vol.get("Throughput", 0),
                        "encrypted": vol.get("Encrypted", False),
                        "kms_key_id": vol.get("KmsKeyId", ""),
                        "snapshot_id": vol.get("SnapshotId", ""),
                        "attached_instance": attached_instance,
                        "device_name": device_name,
                        "multi_attach_enabled": vol.get("MultiAttachEnabled", False),
                    },
                    provider_tags=_tags_to_dict(vol),
                    ems_created_on=vol.get("CreateTime"),
                    relationships=relationships,
                    metrics={"size_gb": vol.get("Size", 0), "iops": vol.get("Iops", 0)},
                )

    def _collect_s3_buckets(self) -> Iterator[ResourceData]:
        """Collect S3 buckets (global resource)."""
        s3 = self._session.client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as exc:
            self.logger.warning("Failed to list S3 buckets: %s", exc)
            return
        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_region = ""
            try:
                loc = s3.get_bucket_location(Bucket=bucket_name)
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
            except Exception:
                bucket_region = "unknown"
            if self._regions and bucket_region not in self._regions and bucket_region != "unknown":
                continue
            yield ResourceData(
                ems_ref=f"arn:aws:s3:::{bucket_name}",
                resource_type_slug="object_storage",
                name=bucket_name,
                canonical_id=f"arn:aws:s3:::{bucket_name}",
                vendor_identifiers={"bucket_name": bucket_name, "account_id": self._account_id},
                vendor_type="S3 Bucket",
                state="active",
                region=bucket_region,
                cloud_tenant=self._account_id,
                properties={"arn": f"arn:aws:s3:::{bucket_name}"},
                ems_created_on=bucket.get("CreationDate"),
            )

    def _collect_rds_instances(self, region: str) -> Iterator[ResourceData]:
        """Collect RDS database instances in a region."""
        rds = self._session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                arn = db.get("DBInstanceArn", "")
                status = db.get("DBInstanceStatus", "unknown")
                endpoint = db.get("Endpoint", {})
                address = endpoint.get("Address", "")
                port = endpoint.get("Port", 0)
                vpc_id = db.get("DBSubnetGroup", {}).get("VpcId", "")
                sg_ids = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
                relationships = []
                if vpc_id:
                    relationships.append({"target_ems_ref": vpc_id, "relationship_type": "member_of"})
                for sg_id in sg_ids:
                    relationships.append({"target_ems_ref": sg_id, "relationship_type": "attached_to"})
                yield ResourceData(
                    ems_ref=arn or db_id,
                    resource_type_slug="relational_db",
                    name=db_id,
                    canonical_id=arn or db_id,
                    vendor_identifiers={"db_instance_id": db_id, "arn": arn, "account_id": self._account_id},
                    vendor_type="RDS Instance",
                    state=RDS_STATE_MAP.get(status, "unknown"),
                    region=region,
                    availability_zone=db.get("AvailabilityZone", ""),
                    cloud_tenant=self._account_id,
                    flavor=db.get("DBInstanceClass", ""),
                    disk_gb=db.get("AllocatedStorage", 0),
                    fqdn=address,
                    properties={
                        "engine": db.get("Engine", ""),
                        "engine_version": db.get("EngineVersion", ""),
                        "db_instance_class": db.get("DBInstanceClass", ""),
                        "multi_az": db.get("MultiAZ", False),
                        "storage_type": db.get("StorageType", ""),
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "port": port,
                        "vpc_id": vpc_id,
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "backup_retention_days": db.get("BackupRetentionPeriod", 0),
                        "security_groups": sg_ids,
                    },
                    provider_tags=_tags_to_dict(db.get("TagList", [])),
                    ems_created_on=db.get("InstanceCreateTime"),
                    relationships=relationships,
                    metrics={"allocated_storage_gb": db.get("AllocatedStorage", 0)},
                )

    def _collect_load_balancers(self, region: str) -> Iterator[ResourceData]:
        """Collect ALB / NLB / GLB via ELBv2."""
        elbv2 = self._session.client("elbv2", region_name=region)
        paginator = elbv2.get_paginator("describe_load_balancers")
        state_map = {"active": "active", "provisioning": "provisioning",
                     "active_impaired": "active", "failed": "error"}
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                arn = lb["LoadBalancerArn"]
                name = lb.get("LoadBalancerName", "")
                lb_type = lb.get("Type", "application")
                vpc_id = lb.get("VpcId", "")
                state_code = lb.get("State", {}).get("Code", "unknown")
                azs = [az.get("ZoneName", "") for az in lb.get("AvailabilityZones", [])]
                relationships = []
                if vpc_id:
                    relationships.append({"target_ems_ref": vpc_id, "relationship_type": "member_of"})
                for sg_id in lb.get("SecurityGroups", []):
                    relationships.append({"target_ems_ref": sg_id, "relationship_type": "attached_to"})
                yield ResourceData(
                    ems_ref=arn,
                    resource_type_slug="load_balancer",
                    name=name,
                    canonical_id=arn,
                    vendor_identifiers={"arn": arn, "dns_name": lb.get("DNSName", ""), "account_id": self._account_id},
                    vendor_type=f"{lb_type.upper()} Load Balancer",
                    state=state_map.get(state_code, "unknown"),
                    region=region,
                    cloud_tenant=self._account_id,
                    fqdn=lb.get("DNSName", ""),
                    properties={
                        "type": lb_type, "scheme": lb.get("Scheme", ""),
                        "vpc_id": vpc_id, "availability_zones": azs,
                        "security_groups": lb.get("SecurityGroups", []),
                        "ip_address_type": lb.get("IpAddressType", ""),
                    },
                    ems_created_on=lb.get("CreatedTime"),
                    relationships=relationships,
                )

    def _collect_lambda_functions(self, region: str) -> Iterator[ResourceData]:
        """Collect Lambda functions in a region."""
        lam = self._session.client("lambda", region_name=region)
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                arn = fn["FunctionArn"]
                name = fn["FunctionName"]
                vpc_id = fn.get("VpcConfig", {}).get("VpcId", "")
                sg_ids = fn.get("VpcConfig", {}).get("SecurityGroupIds", [])
                relationships = []
                if vpc_id:
                    relationships.append({"target_ems_ref": vpc_id, "relationship_type": "member_of"})
                for sg_id in sg_ids:
                    relationships.append({"target_ems_ref": sg_id, "relationship_type": "attached_to"})
                yield ResourceData(
                    ems_ref=arn,
                    resource_type_slug="serverless_function",
                    name=name,
                    canonical_id=arn,
                    vendor_identifiers={"function_name": name, "arn": arn, "account_id": self._account_id},
                    vendor_type="Lambda Function",
                    state="active",
                    region=region,
                    cloud_tenant=self._account_id,
                    memory_mb=fn.get("MemorySize", 0),
                    properties={
                        "runtime": fn.get("Runtime", ""),
                        "handler": fn.get("Handler", ""),
                        "code_size_bytes": fn.get("CodeSize", 0),
                        "timeout_seconds": fn.get("Timeout", 0),
                        "memory_mb": fn.get("MemorySize", 0),
                        "architectures": fn.get("Architectures", []),
                        "package_type": fn.get("PackageType", ""),
                        "role": fn.get("Role", ""),
                        "vpc_id": vpc_id,
                        "last_modified": fn.get("LastModified", ""),
                    },
                    relationships=relationships,
                )

    def _collect_eks_clusters(self, region: str) -> Iterator[ResourceData]:
        """Collect EKS clusters in a region."""
        eks = self._session.client("eks", region_name=region)
        try:
            cluster_names = eks.list_clusters().get("clusters", [])
        except Exception as exc:
            self.logger.warning("Failed to list EKS clusters in %s: %s", region, exc)
            return
        status_map = {"ACTIVE": "active", "CREATING": "provisioning",
                      "DELETING": "decommissioned", "FAILED": "error",
                      "UPDATING": "active", "PENDING": "provisioning"}
        for cluster_name in cluster_names:
            try:
                cluster = eks.describe_cluster(name=cluster_name)["cluster"]
            except Exception as exc:
                self.logger.warning("Failed to describe EKS cluster %s: %s", cluster_name, exc)
                continue
            arn = cluster.get("arn", "")
            status = cluster.get("status", "UNKNOWN")
            vpc_config = cluster.get("resourcesVpcConfig", {})
            vpc_id = vpc_config.get("vpcId", "")
            sg_id = vpc_config.get("clusterSecurityGroupId", "")
            relationships = []
            if vpc_id:
                relationships.append({"target_ems_ref": vpc_id, "relationship_type": "member_of"})
            if sg_id:
                relationships.append({"target_ems_ref": sg_id, "relationship_type": "attached_to"})
            yield ResourceData(
                ems_ref=arn or cluster_name,
                resource_type_slug="container_orchestration_platform",
                name=cluster_name,
                canonical_id=arn or cluster_name,
                vendor_identifiers={"cluster_name": cluster_name, "arn": arn, "account_id": self._account_id},
                vendor_type="EKS Cluster",
                state=status_map.get(status, "unknown"),
                region=region,
                cloud_tenant=self._account_id,
                fqdn=cluster.get("endpoint", ""),
                properties={
                    "kubernetes_version": cluster.get("version", ""),
                    "platform_version": cluster.get("platformVersion", ""),
                    "endpoint": cluster.get("endpoint", ""),
                    "role_arn": cluster.get("roleArn", ""),
                    "vpc_id": vpc_id,
                    "endpoint_public_access": vpc_config.get("endpointPublicAccess", False),
                    "endpoint_private_access": vpc_config.get("endpointPrivateAccess", False),
                },
                ems_created_on=cluster.get("createdAt"),
                relationships=relationships,
            )

    def _collect_auto_scaling_groups(self, region: str) -> Iterator[ResourceData]:
        """Collect Auto Scaling groups in a region."""
        asg_client = self._session.client("autoscaling", region_name=region)
        paginator = asg_client.get_paginator("describe_auto_scaling_groups")
        for page in paginator.paginate():
            for asg in page["AutoScalingGroups"]:
                arn = asg.get("AutoScalingGroupARN", "")
                name = asg["AutoScalingGroupName"]
                vpc_zones = asg.get("VPCZoneIdentifier", "")
                relationships = []
                for inst in asg.get("Instances", []):
                    relationships.append({"target_ems_ref": inst["InstanceId"], "relationship_type": "manages"})
                lt = asg.get("LaunchTemplate", {})
                if not lt:
                    mip = asg.get("MixedInstancesPolicy", {})
                    lt = mip.get("LaunchTemplate", {}).get("LaunchTemplateSpecification", {})
                yield ResourceData(
                    ems_ref=arn or name,
                    resource_type_slug="auto_scaling_group",
                    name=name,
                    canonical_id=arn or name,
                    vendor_identifiers={"asg_name": name, "arn": arn, "account_id": self._account_id},
                    vendor_type="Auto Scaling Group",
                    state="active",
                    region=region,
                    cloud_tenant=self._account_id,
                    properties={
                        "min_size": asg.get("MinSize", 0),
                        "max_size": asg.get("MaxSize", 0),
                        "desired_capacity": asg.get("DesiredCapacity", 0),
                        "current_instances": len(asg.get("Instances", [])),
                        "launch_template": {
                            "id": lt.get("LaunchTemplateId", ""),
                            "name": lt.get("LaunchTemplateName", ""),
                            "version": lt.get("Version", ""),
                        } if lt else {},
                        "health_check_type": asg.get("HealthCheckType", ""),
                        "availability_zones": asg.get("AvailabilityZones", []),
                        "subnet_ids": vpc_zones.split(",") if vpc_zones else [],
                        "target_group_arns": asg.get("TargetGroupARNs", []),
                    },
                    provider_tags={t["Key"]: t.get("Value", "") for t in asg.get("Tags", []) if t.get("Key")},
                    ems_created_on=asg.get("CreatedTime"),
                    relationships=relationships,
                    metrics={
                        "desired_capacity": asg.get("DesiredCapacity", 0),
                        "current_instances": len(asg.get("Instances", [])),
                    },
                )


# -- Helpers ---------------------------------------------------------------

def _get_tag(resource: dict, key: str) -> str:
    for tag in resource.get("Tags", []):
        if tag.get("Key") == key:
            return tag.get("Value", "")
    return ""


def _tags_to_dict(resource) -> dict[str, str]:
    tags_list = resource if isinstance(resource, list) else resource.get("Tags", [])
    return {tag["Key"]: tag.get("Value", "") for tag in tags_list if tag.get("Key")}


def _suggest_inventory_group(os_type: str, tags: dict[str, str]) -> str:
    group = tags.get("ansible_group", "") or tags.get("AnsibleGroup", "")
    if group:
        return group
    if os_type == "windows":
        return "windows"
    if os_type == "linux":
        return "linux"
    return ""
