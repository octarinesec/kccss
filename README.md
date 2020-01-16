# KCCSS
Kubernetes Common Configuration Scoring System

KCCSS aims at providing a frmework to score the risk associated with Kubernetes workloads. 

It is based on the [CVSS](https://www.first.org/cvss/user-guide), and takes inspirations from  [CCSS](https://www.nist.gov/publications/common-configuration-scoring-system-ccss-metrics-software-security-configuration) and [CCE](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/Common-Configuration-Enumeration-(CCE))

To run KCCSS on your clusters, take a look at [https://github.com/octarinesec/kube-scan](kube-scan), an open-source implementation the framework.

This repository contains rules that describes specific rules and remediations, and a script to compute the score of each risk. The [wiki](https://github.com/octarinesec/kccss/wiki) has more detailed information on the rules, the origin and goals of the project, and how to contribute.


![KCCSS rule in kube-scan](https://cdn2.hubspot.net/hubfs/5802044/risk-expanded.png)
