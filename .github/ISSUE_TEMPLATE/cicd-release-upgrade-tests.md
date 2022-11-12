---
name: Release Candidate - Upgrade packages tests 
about: Report the results after running Jenkins tests for the specified release.
title: 'Release [WAZUH VERSION] - Release candidate [RC NUMBER] - Upgrade metrics'
labels: 'team/cicd, type/release tracking'
assignees: ''

---

### Packages tests metrics information
|||
| :-- | :--: |
| **Main release candidate issue** | --- |
| **Main packages metrics issue** | --- |
| **Version** | 4.X.X |
| **Release candidate** | RCX |
| **Tag** | https://github.com/wazuh/wazuh/tree/v4.X.X-rcX |

### Packages used
- Repository: `packages-dev.wazuh.com`
- Package path: `pre-release`
- Package revision: `1`

| Test |
| :--: |
| --- |


---

| System | 3.12.0 | 3.12.3 | 3.13.0 | 3.13.2| 3.13.3 | 3.13.4 | 4.0.0 | 4.0.4 |
| :-- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| CentOS 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 5             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 11 (bullseye) | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 10 (buster)   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 9 (strech)    | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 36            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 35            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 34            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 32            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 31            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Focal         | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Bionic        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Xenial        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Trusty        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Amazon Linux 2       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Amazon Linux 1       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Oracle Linux 8       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| OpenSuse Tumbleweed  | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |


| System | 4.1.0 | 4.1.1 | 4.1.2 | 4.1.3 | 4.1.4 | 4.1.5 |
| :-- | :--: | :--: | :--: | :--: | :--: | :--: |
| CentOS 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 5             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 11 (bullseye) | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 10 (buster)   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 9 (strech)    | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 36            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 35            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 34            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 32            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 31            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Focal         | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Bionic        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Xenial        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Trusty        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Amazon Linux 2       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Amazon Linux 1       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Oracle Linux 8       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| OpenSuse Tumbleweed  | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |


| System | 4.2.0 | 4.2.1 | 4.2.2 | 4.2.3 | 4.2.4 | 4.2.5 | 4.2.6 | 4.2.7 |
| :-- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| CentOS 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| CentOS 5             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 11 (bullseye) | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 10 (buster)   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian 9 (strech)    | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 36            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 35            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 34            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 32            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Fedora 31            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Focal         | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Bionic        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Xenial        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Ubuntu Trusty        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Amazon Linux 2       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Amazon Linux 1       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Oracle Linux 8       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| OpenSuse Tumbleweed  | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Redhat 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |


| System | 4.3.0 | 4.3.1 | 4.3.2 | 4.3.3 | 4.3.4 | 4.3.5 | 4.3.6 | 4.3.7 |
| :-- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| CentOS 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| CentOS 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| CentOS 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| CentOS 5             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Debian 11 (bullseye) | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Debian 10 (buster)   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Debian 9 (strech)    | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Fedora 36            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Fedora 35            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Fedora 34            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Fedora 32            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Fedora 31            | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Ubuntu Focal         | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Ubuntu Bionic        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Ubuntu Xenial        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Ubuntu Trusty        | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Amazon Linux 2       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Amazon Linux 1       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Oracle Linux 8       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| OpenSuse Tumbleweed  | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Redhat 6             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Redhat 7             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |
| Redhat 8             | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |⚫ |

---

| System | MSI Upgrade | Logs | Alerts |
| :-- | :--: | :--: | :--: |
| Windows Server 16 | ⚫ | ⚫ | ⚫ |

---

Legend:
⚫ - Pending/In progress
⚪ - Skipped
🔴 - Rejected
🟢 - Approved
