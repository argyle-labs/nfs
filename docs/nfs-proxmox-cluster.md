# NFS Mounts: VMs vs LXCs on a Proxmox Cluster

This document defines how NFS is used so that **VMs** and **LXCs** have correct storage no matter which Proxmox node they run on.

## Summary

| Type | Where NFS is mounted | Why |
|------|----------------------|-----|
| **VM** | **Inside the VM** (fstab in the VM) | The VM carries its own NFS config. Wherever the VM runs, it boots and mounts NFS from the NAS — same paths, no host dependency. |
| **LXCs** | On the **Proxmox host**, then bind-mounted into the LXC | LXCs use host bind mounts, so each host that runs LXCs must have the same NFS mounts. |

Assume a NAS at `<nas-ip>` exports the shares below.

---

## VMs: Mount NFS inside the VM

A Docker VM should mount NFS **inside the VM**. Use the same mount points and fstab in every such VM so that no matter which Proxmox node the VM runs on, it has the correct mappings.

### Required mount points (inside the VM)

| Mount point (in VM) | NFS export | Purpose |
| ------------------- | ---------- | ------- |
| `/mnt/nfs/media` | `<nas-ip>:/mnt/user/data/media` | Media library |
| `/mnt/nfs/downloads` | `<nas-ip>:/mnt/user/data/downloads` | Downloads |
| `/mnt/nfs/backups` | `<nas-ip>:/mnt/user/data/backups` | Backups |

Same paths in every VM so Docker/compose and apps see consistent volumes.

### Setup inside each VM

**SSH into the VM**, then:

#### 1. Install NFS client (if needed)

**Debian/Ubuntu:**
```bash
sudo apt-get update && sudo apt-get install -y nfs-common
```

**Alpine:**
```bash
apk add nfs-utils
rc-update add rpcbind default
rc-update add nfsmount default
rc-service rpcbind start
```

#### 2. Create mount points

```bash
sudo mkdir -p /mnt/nfs/media /mnt/nfs/downloads /mnt/nfs/backups
```

#### 3. Add NFS entries to fstab (inside the VM)

```bash
sudo cp /etc/fstab /etc/fstab.bak.$(date +%Y%m%d)
sudo nano /etc/fstab
```

Add:

```
# NFS Mounts - NAS (<nas-ip>); same in every VM for HA
<nas-ip>:/mnt/user/data/media      /mnt/nfs/media      nfs  defaults,_netdev,nofail  0  0
<nas-ip>:/mnt/user/data/downloads  /mnt/nfs/downloads  nfs  defaults,_netdev,nofail  0  0
<nas-ip>:/mnt/user/data/backups    /mnt/nfs/backups    nfs  defaults,_netdev,nofail  0  0
```

#### 4. Mount and verify

```bash
sudo mount -a
mount | grep nfs
ls -la /mnt/nfs/backups
```

After that, you can move the VM between nodes; NFS mounts are in the VM and will come up on boot.

---

## LXCs: NFS on the Proxmox host (bind mounts)

LXCs get NFS via **bind mounts from the Proxmox host**. So **each Proxmox node** that runs such LXCs must have the same NFS mounts on the host. Then LXC configs use the same host paths on every node.

### Required host mount points (on every node)

| Host path (on every node) | NFS export | Purpose |
| --------------------------- | ---------- | ------- |
| `/mnt/user/data/media` | `<nas-ip>:/mnt/user/data/media` | Media library |
| `/mnt/user/data/downloads` | `<nas-ip>:/mnt/user/data/downloads` | Downloads |
| `/mnt/user/data/backups` | `<nas-ip>:/mnt/user/data/backups` | Backups (LXC backups, etc.) |

Paths mirror the server so bind mounts are identical on every host.

### Setup on each Proxmox host

Run these steps **on each Proxmox host**.

```bash
sudo mkdir -p /mnt/user/data/media /mnt/user/data/downloads /mnt/user/data/backups
sudo cp /etc/fstab /etc/fstab.bak.$(date +%Y%m%d)
```

Add to `/etc/fstab` on the host:

```
# NFS Mounts - cluster-wide for LXC bind mounts; NAS (<nas-ip>)
<nas-ip>:/mnt/user/data/media      /mnt/user/data/media      nfs  defaults,_netdev,nofail  0  0
<nas-ip>:/mnt/user/data/downloads  /mnt/user/data/downloads  nfs  defaults,_netdev,nofail  0  0
<nas-ip>:/mnt/user/data/backups    /mnt/user/data/backups    nfs  defaults,_netdev,nofail  0  0
```

Then:

```bash
sudo mount -a
```

### LXC bind mount config

In the LXC config (e.g. `/etc/pve/lxc/<vmid>.conf`), use the same host paths on every node:

```ini
mp0: /mnt/user/data/media,mp=/mnt/user/data/media
mp1: /mnt/user/data/downloads,mp=/mnt/user/data/downloads
mp2: /mnt/user/data/backups,mp=/mnt/user/data/backups
```

### Verify host mounts (for LXC)

From your workstation, run a verification script that checks each node has the required host NFS mounts for LXC bind mounts.
