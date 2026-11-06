# credo-ts-openbao, an LF Decentralized Trust Project Security Policy

## About this document

This document defines how security vulnerability reporting is handled in
`credo-ts-openbao`, an LF Decentralized Trust (LFDT) project. The approach aligns
with the [LFDT Security Policy](https://lf-decentralized-trust.github.io/governance/governing-documents/security/).
Please review that document to understand the basis of security reporting for
this project.

This vulnerability policy borrows heavily from the recommendations of the OpenSSF
Vulnerability Disclosure working group. For up-to-date information on the latest
recommendations related to vulnerability disclosures, please visit the
[GitHub of that working group](https://github.com/ossf/wg-vulnerability-disclosures).

If you are already familiar with the security policies of `credo-ts-openbao` and
are ready to report a vulnerability, jump to [Report Intakes](#report-intakes).

## Outline

- [About this document](#about-this-document)
- [What Is a Vulnerability Disclosure Policy?](#what-is-a-vulnerability-disclosure-policy)
- [Security Team](#security-team)
- [Discussion Forums](#discussion-forums)
- [Report Intakes](#report-intakes)
- [CNA/CVE Reporting](#cnacve-reporting)
- [Embargo List](#embargo-list)
- [(GitHub) Security Advisories](#github-security-advisories)
- [Private Patch Deployment Infrastructure](#private-patch-deployment-infrastructure)

## What Is a Vulnerability Disclosure Policy?

No piece of software is perfect. All software (at least, all software of a
certain size and complexity) has bugs. In open source development, members of the
community or the public find bugs and report them to the project. A vulnerability
disclosure policy explains how this process functions from the perspective of the
project.

This vulnerability disclosure policy explains the rules and guidelines for
`credo-ts-openbao`. It is intended to act as both a reference for outsiders,
including bug reporters and those looking for information on the project's
security practices, as well as a set of rules that maintainers and contributors
have agreed to follow.

## Security Team

The current `credo-ts-openbao` security team is:

| Name | Email ID | Discord ID | Area/Specialty |
| --- | --- | --- | --- |
| Ajay Jadhav | [ajay@ayanworks.com](mailto:ajay@ayanworks.com) | ajile_in | Maintainer |
| Amit Padmani | [amit.padmani@ayanworks.com](mailto:amit.padmani@ayanworks.com) | amitpadmani | Maintainer |
| Ankita Patidar | [ankita.patidar@ayanworks.com](mailto:ankita.patidar@ayanworks.com) | ankita_p | Maintainer |

The security team must include at least three project Maintainers that agree to
carry out the duties and responsibilities below. Members are added and removed
from the team via approved pull requests to this repository. For additional
background on the role of the security team, see the
[People Infrastructure](https://lf-decentralized-trust.github.io/governance/governing-documents/security/#people-infrastructure)
section of the LFDT Security Policy.

**Responsibilities:**

1. Acknowledge receipt of vulnerability reports to the reporter within two
   business days.
2. Assess the issue. Engage with the reporter to ask any outstanding questions
   about the report and how to reproduce it. If the report was received by email
   and may be a security vulnerability, open a GitHub Security Advisory on the
   repository to manage the report. If the report is not considered a
   vulnerability, inform the reporter and stop this process. If the report is a
   regular bug, inform the reporter of the normal issue process.
3. Some issues require more time and resources to correct. If a report is
   complex, discuss an embargo period with the reporter during which the report
   will not be publicly disclosed. The embargo period must be negotiated with the
   reporter and must not be longer than 90 days.
4. If necessary, create private patch development infrastructure for the issue by
   emailing the [LFDT Community Architects](mailto:community-architects@lfdecentralizedtrust.org).
5. Request a CVE for the issue (see [CNA/CVE Reporting](#cnacve-reporting)).
6. Decide the date for public release of the vulnerability report, when the
   embargo period ends.
7. If applicable, notify members of the embargo list of the vulnerability,
   upcoming patch and release.
8. Publish a new release in which the vulnerability is addressed.
9. Publicly disclose the issue within 48 hours after the release via a GitHub
   Security Advisory (see [(GitHub) Security Advisories](#github-security-advisories)).

## Discussion Forums

Discussions about each reported vulnerability should be carried out in the
private GitHub Security Advisory about the vulnerability. If necessary, a private
channel specific to the issue may be created on the LFDT Discord server with
invited participants added to the discussion.

## Report Intakes

`credo-ts-openbao` has the following ways to submit security vulnerabilities.
While the security team will do its best to respond to bugs disclosed in all
possible ways, reporters are encouraged to use the following approved channels:

- Email the [LFDT Foundation security list](mailto:security@lists.lfdecentralizedtrust.org):
  include the project/repository name, a description of the issue, the steps you
  took to create the issue, affected versions, and, if known, mitigations. If
  triaging the email determines that the issue may be a security vulnerability, a
  [GitHub security vulnerability report](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
  will be opened.
- Open a [GitHub security vulnerability report](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability):
  open a draft security advisory on the "Security" tab of this GitHub repository.
  See [(GitHub) Security Advisories](#github-security-advisories).

## CNA/CVE Reporting

`credo-ts-openbao` maintains a list of **Common Vulnerabilities and Exposures
(CVE)** and uses GitHub as its **CVE numbering authority (CNA)** for issuing
CVEs.

## Embargo List

`credo-ts-openbao` maintains a private embargo list. If you wish to be added to
the embargo list, please email the
[LFDT Foundation security mailing list](mailto:security@lists.lfdecentralizedtrust.org),
including the project name (`credo-ts-openbao`) and the reason for being added to
the embargo list. Requests will be assessed by the `credo-ts-openbao` security
team in conjunction with the appropriate LFDT staff, and a decision will be made
whether to accommodate the request.

For more information about the embargo list, see the
[Embargo List section of the LFDT Security Policy](https://lf-decentralized-trust.github.io/governance/governing-documents/security/#embargo-list).

## (GitHub) Security Advisories

`credo-ts-openbao` uses GitHub Security Advisories to manage the public
disclosure of security vulnerabilities.

## Private Patch Deployment Infrastructure

In creating patches and new releases that address security vulnerabilities,
`credo-ts-openbao` uses the private development features of GitHub for security
vulnerabilities. GitHub has
[extensive documentation](https://docs.github.com/en/code-security/security-advisories/repository-security-advisories)
about these features.
