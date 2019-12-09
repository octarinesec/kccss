# KCCSS
Kubernetes Common Configuration Scoring System

KCCSS aims at providing a frmework to score the risk associated with Kubernetes workloads. 

It is based on the [CVSS](https://www.first.org/cvss/user-guide), and takes inspirations from  [CCSS](https://www.nist.gov/publications/common-configuration-scoring-system-ccss-metrics-software-security-configuration) and [CCE](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/Common-Configuration-Enumeration-(CCE))

For more information, check out the website [kccss.io](https://kccss.io).

This repository contains rules that describes specific rules and remediations, and a script to compute the score of each risk.