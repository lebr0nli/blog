---
permalink: /about/
title: "About me"
last_modified_at: 2025-10-25 10:15:00 +0800
toc: true
toc_sticky: true
---

## whoami

- Alan Li ≡ alanlitw ≡ lebr0nli ≡ a nobody

## pwd

- /Users/NYCU

## ls ~/favorites

- web/
- pwn/
- breaking\ sandbox/
- CTF/
- Bug\ Bounty/
- programming/
- rock'n'roll/

## Work Experience

- Researcher Intern @ _DEVCORE_
  - Find and report 0-day vulnerabilities in various applications (mostly web applications)
    - My most significant finding was the critical vulnerabilities in [Zimbra Collaboration Suite](https://en.wikipedia.org/wiki/Zimbra), including XSS, SSRF, and Pre-Auth RCE
      - You can check Zimbra's [security advisories](https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories) for more details
  - _September 2023 - July 2024_

## Vulnerability Reports

| Company / Product          | Vulnerability                                   | Time    |
| -------------------------- | ----------------------------------------------- | ------- |
| Mozilla Firefox            | connect-src CSP Bypass (CVE-2025-6427)          | 2025.06 |
| Zimbra Collaboration Suite | OS Command Injection (CVE-2024-45519)           | 2024.09 |
| Zimbra Collaboration Suite | Server-Side Request Forgery (CVE-2024-45518)    | 2024.09 |
| Zimbra Collaboration Suite | Cross-Site Scripting (CVE-2024-45517)           | 2024.09 |
| Zimbra Collaboration Suite | Cross-Site Scripting (CVE-2024-45516)           | 2024.09 |
| Zimbra Collaboration Suite | Cross-Site Scripting (CVE-2024-45515)           | 2024.09 |
| Zimbra Collaboration Suite | Cross-Site Scripting (CVE-2024-45514)           | 2024.09 |
| QNAP - Video Station       | OS Command Injection (CVE-2023-47563)           | 2024.09 |
| QNAP - QuFirewall          | Path Traversal (CVE-2023-41290, CVE-2023-41291) | 2024.04 |
| QNAP - Photo Station       | OS Command Injection (CVE-2023-47562)           | 2024.02 |
| QNAP - Photo Station       | Cross-site Scripting (CVE-2023-47561)           | 2024.02 |
| QNAP - QuMagie             | OS Command Injection (CVE-2023-47560)           | 2024.01 |
| QNAP - QuMagie             | Cross-site Scripting (CVE-2023-47559)           | 2024.01 |
| QNAP - QcalAgent           | OS Command Injection (CVE-2023-41289)           | 2024.01 |
| Quizlet                    | REDACTED (Priority 2 on Bugcrowd)               | 2022.02 |
| Dcard                      | Insecure Direct Object References               | 2021.11 |
| Quizlet                    | REDACTED (Priority 3 on Bugcrowd)               | 2021.09 |
| Quizlet                    | REDACTED (Priority 3 on Bugcrowd)               | 2021.08 |
| Dcard                      | Open Redirect                                   | 2021.07 |
| Dcard                      | Open Redirect                                   | 2020.09 |
| Dcard                      | Insecure Direct Object References               | 2020.08 |
| Dcard                      | Insecure Direct Object References               | 2020.08 |

## CTF (Capture the Flag)

| Name                                             | Participated as                | Rank              | Time    | Location       |
| ------------------------------------------------ | ------------------------------ | ----------------- | ------- | -------------- |
| Flare-On 12                                      | lebr0nli (individual)          | 69th Finisher     | 2025.10 | remote         |
| Asian Cyber Security Challenge                   | lebr0nli (individual)          | 12th (Taiwan 2nd) | 2024.04 | remote         |
| AIS3 EOF Final                                   | YAATN ain't a team name (team) | 1st               | 2024.02 | New Taipei, TW |
| AIS3 EOF Quals                                   | lebr0nli (individual)          | 2nd               | 2024.01 | remote         |
| HITCON CTF Final                                 | Blue Water (team)              | 9th               | 2023.11 | Taipei, TW     |
| Balsn CTF                                        | ${CyStick} (team)              | 3rd               | 2023.11 | remote         |
| SECCON CTF Quals                                 | ${CyStick} (team)              | 2nd               | 2023.09 | remote         |
| HITCON CTF Quals                                 | Blue Water (team)              | 1st               | 2023.09 | remote         |
| Asian Cyber Security Challenge                   | lebr0nli (individual)          | 35th (Taiwan 6th) | 2023.02 | remote         |
| HITCON CTF                                       | Water Paddler (team)           | 11th              | 2022.11 | remote         |
| Google Capture The Flag Final Stage (Hackceler8) | Water Paddler (team)           | Finalist          | 2022.09 | London, UK     |
| Google Capture The Flag Qualification            | Water Paddler (team)           | 5th               | 2022.07 | remote         |
| ångstromCTF                                      | Water Paddler (team)           | 3rd               | 2022.05 | remote         |
| Asian Cyber Security Challenge                   | lebr0nli (individual)          | 56th (Taiwan 6th) | 2021.09 | remote         |
| AIS3 Pre-Exam                                    | e^iπ+1day (individual)         | 6th               | 2021.05 | remote         |

> I started to play CTF since early 2021.
>
> From May 2022, I joined [Water Paddler](https://ctftime.org/team/155019).
>
> From August 2023, I also joined [${CyStick}](https://ctftime.org/team/264915).
>
> I usually post my write-ups on this blog, but sometimes/recently I'm too lazy to write them down so I just post my solve scripts on my [GitHub Gist](https://gist.github.com/lebr0nli) :p

## Side Project

- [GEP (GDB Enhanced Prompt)](https://github.com/lebr0nli/GEP)
  - Enhance your GDB with fzf history search, fish-like autosuggestions, tab auto-completion with fzf, and more!
  - Python
  - GDB plug-in

- [PHPFun](https://github.com/lebr0nli/PHPFun)
  - PHP obfuscator
  - Python CLI
  - Simple Web Interface with Brython
  - CTF tool

## Open Source Contribution

- [pwndbg](https://github.com/pwndbg/pwndbg)
  - Exploit Development and Reverse Engineering with GDB Made Easy
  - Python
  - My [commits](https://github.com/pwndbg/pwndbg/commits?author=lebr0nli)

- [one_gadget](https://github.com/david942j/one_gadget)
  - The best tool for finding one gadget RCE in libc.so.6
  - Ruby
  - My [commits](https://github.com/david942j/one_gadget/commits?author=lebr0nli)

- [Hackbar](https://github.com/0140454/hackbar)
  - A browser extension for Penetration Testing
  - Javascript
  - My [commits](https://github.com/0140454/hackbar/commits?author=lebr0nli)

## Certification

| Name                                                  | Time |
| ----------------------------------------------------- | ---- |
| OffSec Certified Expert 3 (OSCE³)                     | 2025 |
| PEN-300: OffSec Experienced Penetration Tester (OSEP) | 2025 |
| EXP-301: OffSec Exploit Developer (OSED)              | 2025 |
| WEB-300: OffSec Web Expert (OSWE)                     | 2025 |
| PEN-200: OffSec Certified Professional (OSCP)         | 2025 |
| WEB-200: OffSec Web Assessor (OSWA)                   | 2025 |
