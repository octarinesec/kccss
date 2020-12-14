## Kubernetes Common Configuration Scoring System (KCCSS)

With over 30 security settings under the control of every single developer, you need to be a Kubernetes expert to understand if the final configuration introduces a high risk to your cluster. With a single change to a single file you can open your entire Kubernetes cluster to privilege escalations, attacks, leak secrets, risk confidential data, or accidentally give public access to private services. 

KCCSS is a framework for rating security risks associated with misconfigurations. 

# A standard way to determine risky workloads due to configs

KCCSS is similar to the Common Vulnerability Scoring System ([CVSS](https://www.first.org/cvss/user-guide)), the industry-standard for rating vulnerabilities, but instead focuses on the Kubernetes configurations and security settings themselves. Vulnerabilities are always detrimental, but configuration settings can be insecure, neutral, or critical for protection or remediation. KCCSS scores both risks and remediations as separate rules, and allows users to calculate risk for every runtime setting from 0 to 10, with 10 being the most at risk, then calculates the global risk of the workloads overall.

The scoring formula as well as the risk and remediation rules are open-source, and available in this repository. The list of rules can be easily expanded to include vendor-specific remediations, risks and remediations for different Kubernetes distributions or cloud providers, or risks and remediations for additional tools installed (Service Mesh, Helm server, etc.). We want to build a community around KCCSS and we encourage any kind of contribution, review of existing rules, new rules, better formulas, and so on.

KCCSS shows the potential impact of risky configuration settings in three areas:
* Confidentiality: exposure of PII, potential access to secrets, PII, etc.
* Integrity: unwanted changes to the container, host or cluster such as being able to change the runtime behavior, launch new processes, new pods, etc.
* Availability: exhaustion of resources, Denial of Service, etc.

Then, KCCSS takes into account the blast radius (risk is limited to the container, or can affect the entire cluster), the ease of exploiting the risk, and whether an attack would require local access—or can be done remotely—to rate the risk. It combines all of the security risks associated with a workload, along with the required remediations, to attribute an overall risk score to the workload.

# A common language across teams

KCCSS makes it easy to talk about security across teams in your organization. DevOps teams can track the high risk workloads. Developers see what settings are impacting the security of their services, and can decide to either change those settings, or bring down the risk level to an acceptable level. Compliance or Business teams get a clear understanding of the potential impact of the risk and can decide whether it is acceptable or not.

# Add your own rules

We designed KCCSS to be easily expanded by others, whether they are security vendors, open-source developers or Kubernetes users. You can easily add rules to represent risks or remediations brought by different Kubernetes tools and services to ensure you have a comprehensive view of your security posture. We welcome all contributions from the community and other vendors, so please join us to make improvements to existing rules, create new generic Kubernetes rules, vendors rules, etc.

We have additional documentation in the [wiki](https://github.com/octarinesec/kccss/wiki) that explains how the rules are created, the meaning of the different fields and the formula to compute each score. We will be adding more tools and more documentation in the coming days.