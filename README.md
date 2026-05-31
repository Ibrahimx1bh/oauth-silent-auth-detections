# OAuth Silent Authentication Abuse - Detection Rules

Detection content for identifying abuse of OAuth/OIDC `prompt=none` silent authentication for phishing redirection.

## Background

Attackers register OAuth applications in their own tenant, configure a redirect URI pointing to attacker-controlled infrastructure, and distribute authorization URLs containing `prompt=none` via phishing emails. When victims click the link, the identity provider attempts silent authentication, fails, and redirects the victim to the attacker's endpoint through a protocol-compliant error redirect. The initial URL originates from a trusted domain (`login.microsoftonline.com`), bypassing URL reputation checks and reducing user suspicion.

Full technical analysis: [Medium article](https://medium.com/@ibrahimxibh/oauth-silent-authentication-abuse-in-microsoft-entra-id-the-protocol-mechanics-behind-modern-7cd2004829df)

## Detection Strategy

### Why `prompt=none` in Email is the Strongest Signal

Silent SSO requests (`prompt=none`) are generated programmatically by client-side libraries (MSAL.js, ADAL.js) and execute in hidden iframes or background HTTP requests. They are **never** delivered as clickable email links.

There is no legitimate workflow where a user receives an email containing a `prompt=none` authorization URL. The delivery mechanism itself is the anomaly. This makes email-layer detection effective without additional correlation.

### What Entra ID Sign-In Logs Actually Show

POC testing confirmed the following behavior in the victim tenant's sign-in logs when a user clicks a `prompt=none` phishing link:

| Field | Value | Notes |
|---|---|---|
| Sign-in type | **Non-interactive** | Not visible in Interactive sign-in logs |
| Application name | Attacker-controlled | Whatever the attacker named the app |
| Resource | Depends on scopes | POC showed Microsoft Graph with openid/profile/User.Read scopes |
| Status | **Interrupted** | Not "Failure" |
| Error code | None visible | No error code in the log entry |

This means detection at the identity layer cannot rely on error codes. It must rely on **Application ID** (the one field an attacker cannot spoof) cross-referenced against an approved application baseline.

## Detection Matrix

| # | File | Layer | Signal | Description |
|---|---|---|---|---|
| 1 | `email-prompt-none.kql` | Mail Gateway | **High** | `prompt=none` in email-delivered OAuth URLs |
| 2 | `email-redirect-url-misdirection.kql` | Mail Gateway | **Critical** | `prompt=none` + non-standard `redirect_url` parameter |
| 3 | `identity-unfamiliar-appid.kql` | Identity | **Medium** | Unfamiliar AppId with Interrupted status in non-interactive logs |
| 4 | `identity-campaign-detection.kql` | Identity | **High** | Same AppId across multiple accounts in short window |
| 5 | `oauth-silent-auth-email.yml` | Mail Gateway | **High** | Sigma: `prompt=none` in email URLs |
| 6 | `oauth-redirect-url-misdirection.yml` | Mail Gateway | **Critical** | Sigma: `prompt=none` + `redirect_url` misdirection |
| 7 | `oauth-unfamiliar-appid.yml` | Identity | **Medium** | Sigma: Unfamiliar AppId in non-interactive sign-ins |
| 8 | `oauth-campaign-detection.yml` | Identity | **High** | Sigma: Same AppId across multiple accounts (campaign) |
| 9 | `proxy-prompt-none-redirect.yml` | Network | **Medium** | Sigma: OAuth error redirect to external hosting platform |

## MITRE ATT&CK Mapping

| Technique | Name | Context |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | OAuth URL delivered via email |
| T1078.004 | Valid Accounts: Cloud Accounts | Abuse of OAuth application registration |
| T1036.005 | Masquerading: Match Legitimate Name or Location | URL originates from trusted IdP domain |
| T1071.001 | Application Layer Protocol: Web Protocols | OAuth/OIDC as redirect mechanism |

## Requirements

| Query | Data Source |
|---|---|
| KQL 1-2 | Microsoft Defender for Office 365 (EmailUrlInfo, EmailEvents, UrlClickEvents) |
| KQL 3-4 | Microsoft Sentinel (SigninLogs) or Defender XDR (AADSignInEventsBeta) |
| Sigma (email) | SIEM with email URL inspection capability |
| Sigma (identity) | SIEM with Azure AD sign-in log ingestion |
| Sigma (proxy) | Web proxy logs with HTTP Referer and full URI fields |

## Tuning Notes

- **Mail gateway queries** require minimal tuning. False positives are near zero for query 1 and effectively zero for query 2.
- **Identity queries** require an approved Application ID baseline. Maintain this as a Watchlist in Sentinel or a reference table. New third-party integrations will need to be added to the baseline as they are onboarded.
- **Identity queries require further testing.** The "Interrupted" status, non-interactive classification, and Microsoft Graph resource were observed during controlled POC testing with specific scope configurations (openid, profile, User.Read). Behavior may vary with different attacker scope configurations, tenant Conditional Access policies, or Entra ID updates. Run as hunting queries first to establish baseline noise in your environment before deploying as automated alerts. The ResourceDisplayName filter is commented out in the KQL queries and omitted from Sigma rules to avoid missing attacks that use different scopes.
- **Proxy Sigma rule** is a supporting signal and should not be used standalone. Cross-reference with mail gateway and identity layer detections.

## References

- [OAuth Silent Authentication Abuse - Full Technical Analysis](https://medium.com/@ibrahimxibh/oauth-silent-authentication-abuse-in-microsoft-entra-id-the-protocol-mechanics-behind-modern-7cd2004829df)
- [OpenID Connect Core 1.0 - prompt parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- [RFC 9700 Section 4.11.2 - Authorization Server as Open Redirector](https://www.rfc-editor.org/rfc/rfc9700#section-4.11.2)
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)