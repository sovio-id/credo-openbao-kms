# Security Policy

## About this document

This document defines how security vulnerability reporting is handled in
this project.

This vulnerability policy borrows heavily from the recommendations of the OpenSSF
Vulnerability Disclosure working group. For up-to-date information on the latest
recommendations related to vulnerability disclosures, please visit the
[GitHub of that working group](https://github.com/ossf/wg-vulnerability-disclosures).

If you are already familiar with this security policy and are ready to report a
vulnerability, jump to [Report Intakes](#report-intakes).

## Outline

- [About this document](#about-this-document)
- [What Is a Vulnerability Disclosure Policy?](#what-is-a-vulnerability-disclosure-policy)
- [Security Team](#security-team)
- [Discussion Forums](#discussion-forums)
- [Report Intakes](#report-intakes)
- [CNA/CVE Reporting](#cnacve-reporting)
- [(GitHub) Security Advisories](#github-security-advisories)
- [Private Patch Deployment Infrastructure](#private-patch-deployment-infrastructure)

## What Is a Vulnerability Disclosure Policy?

No piece of software is perfect. All software (at least, all software of a
certain size and complexity) has bugs. In open source development, members of the
community or the public find bugs and report them to the project. A vulnerability
disclosure policy explains how this process functions from the perspective of the
project.

This vulnerability disclosure policy explains the rules and guidelines for this
project. It is intended to act as both a reference for outsiders, including bug
reporters and those looking for information on the project's security practices,
as well as a set of rules that maintainers and contributors have agreed to
follow.

## Security Team

The security team is made up of the project maintainers with admin access to
this repository. Reports reach them through the private GitHub Security Advisory
intake described in [Report Intakes](#report-intakes); there is no separate
security email address.

**Responsibilities:**

1. Acknowledge receipt of vulnerability reports to the reporter within two
   business days.
2. Assess the issue. Engage with the reporter to ask any outstanding questions
   about the report and how to reproduce it. If the report is not considered a
   vulnerability, inform the reporter and stop this process. If the report is a
   regular bug, inform the reporter of the normal issue process.
3. Some issues require more time and resources to correct. If a report is
   complex, discuss an embargo period with the reporter during which the report
   will not be publicly disclosed. The embargo period must be negotiated with the
   reporter and must not be longer than 90 days.
4. If necessary, create a temporary private fork from the GitHub Security
   Advisory to develop the patch (see
   [Private Patch Deployment Infrastructure](#private-patch-deployment-infrastructure)).
5. Request a CVE for the issue (see [CNA/CVE Reporting](#cnacve-reporting)).
6. Decide the date for public release of the vulnerability report, when the
   embargo period ends.
7. Publish a new release in which the vulnerability is addressed.
8. Publicly disclose the issue within 48 hours after the release via a GitHub
   Security Advisory (see [(GitHub) Security Advisories](#github-security-advisories)).

## Discussion Forums

Discussions about each reported vulnerability should be carried out in the
private GitHub Security Advisory about the vulnerability, with invited
participants added to the advisory as needed.

## Report Intakes

Report security vulnerabilities privately through GitHub:

- Open a [GitHub security vulnerability report](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability):
  use "Report a vulnerability" on the "Security" tab of this GitHub repository.
  Include a description of the issue, the steps to reproduce it, affected
  versions and, if known, mitigations. See
  [(GitHub) Security Advisories](#github-security-advisories).

**Do not open a public issue, pull request or discussion for a security
vulnerability.**

## CNA/CVE Reporting

This project uses GitHub as its **CVE numbering authority (CNA)** for issuing
**Common Vulnerabilities and Exposures (CVE)** identifiers.

## (GitHub) Security Advisories

This project uses GitHub Security Advisories to manage the public disclosure of
security vulnerabilities.

## Private Patch Deployment Infrastructure

In creating patches and new releases that address security vulnerabilities, this
project uses the private development features of GitHub for security
vulnerabilities. GitHub has
[extensive documentation](https://docs.github.com/en/code-security/security-advisories/repository-security-advisories)
about these features.
