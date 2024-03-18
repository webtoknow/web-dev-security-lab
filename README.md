# Web developers security labs

![GitHub repo size](https://img.shields.io/github/repo-size/webtoknow/web-dev-security-lab)

Web development security labs consist of lectures designed to introduce developers to the OWASP Top 10 list, which highlights the most critical security risks to web applications. During these sessions, we utilize OWASP Juice Shop, known as one of the most insecure web applications, to demonstrate these vulnerabilities. The lectures are divided into two parts: an introduction to the issues and exercises where we actively engage in hacking Juice Shop to experience these vulnerabilities firsthand.

University lecture on "IT Security" as
[Open Educational Resources](https://www.unesco.org/en/communication-information/open-solutions/open-educational-resources)
created by [Björn Kimminich](http://kimminich.de) and modified by [Bogdan Mihai Nicolae](http://bogminic.com). You can find the original material at [it-security-lecture](https://github.com/bkimminich/it-security-lecture).

## Application Security & SDLC

1. [Open Web Application Security Project](slides/01-01-owasp.md)(OWASP)

   This lecture introduces OWASP, a nonprofit foundation focused on improving software security. It covers OWASP's core values, projects, project lifecycle, chapters, and mandatory chapter rules. The lecture also incorporates exercises to help you become acquainted with Juice Shop.

2. [Injection](slides/01-02-injection.md)

   The lecture discusses injection attacks, which involve tricking an application into executing unintended commands. It covers various types of interpreters that are vulnerable to injection attacks. The exercises involve becoming acquainted with SQL injection and bypassing authentication in Juice Shop.

3. [Cross-Site Scripting (XSS)](slides/01-03-xss.md)

   This lecture covers Cross-Site Scripting (XSS), a common web application vulnerability. It explains the root cause, typical impacts, and provides a phishing email example. It also includes a demo of an XSS attack and discusses vulnerable code examples.

4. [Authentication Flaws](slides/01-04-authentication_flaws.md)

   This lecture delves into Authentication Flaws, a common security issue in web development. It discusses the importance of secure authentication, common mistakes, and potential impacts. Exercises include identifying and exploiting authentication flaws in Juice Shop.

5. [Authorization Flaws](slides/01-05-authorization_flaws.md)

   This lecture focuses on Authorization Flaws, a prevalent security concern in web applications. It covers the principles of secure authorization, common pitfalls, and their potential consequences. Practical exercises involve identifying and exploiting authorization flaws in the most unsecure application in the world aka Juice Shop.

6. [Cryptographic Failures](slides/01-06-cryptographic_failures.md)

   This lecture explores Cryptographic Failures, a significant security risk in software development. It highlights the importance of proper encryption, common errors, and their potential effects. Hands-on exercises involve identifying and exploiting cryptographic failures in a secure environment.

7. [Insecure Dependencies & Configuration](slides/01-07-insecure_dependencies_and_configuration.md)

   This lecture examines Insecure Dependencies and Configuration, a critical security issue in software development. It emphasizes the need for secure dependencies and configurations, common oversights, and their potential repercussions. Exercises include identifying and exploiting these flaws in Juice Shop safe context.

8. [Software & Data Integrity Failures](slides/01-08-integrity_failures.md)

   This lecture investigates Integrity Failures, a serious security concern in software development. It underscores the importance of data integrity, common missteps, and their potential implications. Practical exercises involve identifying and exploiting integrity failures by hacking Juice Shop.

9. [Secure Development Lifecycle](slides/01-09-sdlc.md)

   This lecture discusses the Software Development Life Cycle (SDLC), a crucial process in software development. It covers the different stages of SDLC, common vulnerabilities at each stage, and their potential impacts. Exercises involve understanding and applying secure SDLC practices.

## Create PDF files

The `marp-team/marp-cli` is a command-line interface for Marp and Marpit Markdown. It is a powerful tool that allows you to convert your Markdown files into HTML, PDF, PPTX (PowerPoint), or images. This is particularly useful for creating presentations or documents from your Markdown files.

To create a PDF from your Markdown files, you can use the following command:

```bash
npx @marp-team/marp-cli@latest
```

that is usign [`.marprc`](.marprc) configuration file.

----

[![CC BY SA 4.0](cc_by-sa_4.0.svg)](https://creativecommons.org/licenses/by-sa/4.0/)

This work is licensed under a
[Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
