# Privacy and security basis

Reviewed sources on 6 October 2026; this is technical scoping, not legal certification.

## Field assessment
| Field | Treatment | Scope reasoning |
|---|---|---|
| Full name | Required; encrypted; self only | UU PDP Article 4(3) expressly names full name as general personal data; GDPR Article 4 covers identifiable persons. |
| Username | Required; encrypted plus keyed lookup; visible as owner only with listing/grant | Identifying/online identifier; pseudonymity does not make it anonymous. |
| Email | Required; encrypted plus keyed lookup; self only | Identifying contact detail; no marketing/recovery/verification messages. Collection supports assignment profile and unique account identity; not proof of email control. |
| Password | Required; salted Argon2id hash; never returned | Secret credential tied to identity; reversible ciphertext is not the password storage approach. |
| Birthday | Optional; encrypted; self only | Identifying when linked to account, but not required by either law for this application. No demonstrated operational need to make it mandatory. |

These laws do not mandate this specific five-field collection. GDPR Article 5(1)(c) requires adequate/relevant/necessary data; Article 2/3 applicability depends on actual activity and territorial scope. UU PDP Article 1(1) covers direct/combined identification and Article 4 distinguishes general/specific data. Birthdays do not become a specific category merely by being dates; children's data has specific treatment under UU PDP, and images/documents can contain other sensitive data. Do not add ID number, address, gender, or other profile fields merely because the assignment mentions private data. ID-card images are uploaded files, not mandatory account verification.

## Dataset and notice
Baseline classroom use is synthetic profiles and mock ID images. Before registration provide privacy notice with responsible project team/contact configured in deployment, purpose, field treatment, educational algorithms, server-side decryption, listing/grants, retention, deletion/export and limitations. No bundled placeholder contact presented as a real controller. Configuration validation requires an actual classroom project contact before deployment. Record notice version acknowledgement; not a universal lawful-basis claim. An actual real-person deployment needs a separate applicability/lawful-basis assessment, including children; outside baseline scope.

Homepage listing confirmation states: “Logged-in users will see this filename and your username. They cannot download it unless you grant permission.” Metadata can itself reveal personal information. No profile fields disclosed to recipients beyond owner username. Grant recipients can keep downloaded copies. Withdraw listing and revoke grant are separate controls.

Account profile export contains only the user's profile values, excluding password/hash, lookup tokens, and keys. Account deletion is available; require password and warn about permanent loss. Retention: active content until owner/account deletes; sessions expire within 12 hours; in-memory throttling counters within 1 hour; operational noncontent logs 7 days; encrypted backups 7 days. Rows do not guarantee physical erasure; see data-model caveat.

## Threat model
Protect against unauthorized logged-in users, enumeration, IDOR, SQL injection, XSS/CSRF, malicious uploads, corrupted/swapped ciphertext, session theft mitigation, and accidental plaintext disclosure. Root-key/server compromise defeats server-side protection. Database theft exposes technical access graphs and weak cipher copies; strong AES copies cannot compensate for weak RC4/DES copies of the same plaintext. HMAC adds integrity, not missing DES confidentiality. No claim of production security.

## Authentication and web controls
Opaque 32-byte CSPRNG session token in HttpOnly/Secure/SameSite=Lax cookie, Path=/; use __Host- prefix under HTTPS. Store SHA-256 token digest; 12-hour absolute expiry, no indefinite renewal. Rotate token on login; logout/change-password invalidates sessions. Current password required to change password/email and delete account. CSRF double-submit is not used: derive a per-session 32-byte CSRF token as SHA-256 over UTF-8 domain prefix ciphervault-csrf-v1 followed by the raw 32-byte CSPRNG session token; return its base64url encoding from login/session endpoint, store token digest, require X-CSRF-Token on all state-changing authenticated calls plus Origin verification. Login/register verify same-origin Origin and are rate-limited. Separate localhost development cookie config; never use it in deployment.

Login rate limit defaults: 5 attempts/minute per normalized username keyed digest and 20/minute per source address; no permanent account lock. Registration 5/hour/address; grant resolution 20/minute/user; bounded concurrent password hashing. Counters in memory only; restart resets them. Do not store raw IPs in application logs. Generic credentials failure; email/username registration conflict returns generic identity-conflict without specifying which.

## Upload controls
Extension + server MIME sniff + bounded structure checks. JPEG/PNG/WebP decode headers only within pixel limits (max 40 million pixels); no thumbnails. PDF magic is not proof of harmlessness. Office OLE distinguish document/spreadsheet structure; DOCX/XLSX check expected ZIP entries with no extraction, max 1000 entries and 100 MiB declared expanded size; reject encrypted/unknown Office containers. Recognize supported video container signatures; no transcoding. MIME/extension mismatch → 415. Strip path components, reject control/bidi control characters and invalid/oversize filename (1–180 characters); preserve extension on rename. Content-Disposition safely encoded. Content-Type comes from validated type, X-Content-Type-Options: nosniff and Cache-Control: no-store. Do not send inline disposition.

## Sources
- UU No.27/2022 official text, Articles 1/4/5–9/20: https://peraturan.bpk.go.id/Home/Download/224884/UU%20Nomor%2027%20Tahun%202022.pdf
- GDPR official text, Articles 2–5: https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng
- EDPB personal-data explanation: https://www.edpb.europa.eu/sme/learn-the-basics/data-protection-basics_en
- European Commission data minimisation: https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/principles-gdpr_en
- OWASP crypto storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP password storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Go RC4/DES: https://pkg.go.dev/crypto/rc4 ; https://pkg.go.dev/crypto/des
- Go cipher package: https://pkg.go.dev/crypto/cipher

## Session initialization
CSRF plaintext token lives in browser memory and is reconstructed from the raw cookie session token with the fixed domain-separated derivation above; SQL stores digest only. GET session returns the same CSRF token without mutation, so browser reloads/tabs work. Rotate the session token on login; derive and store its new CSRF digest together. APIs never rely on an owner-supplied username/file ID as proof of identity. General request size cap accommodates multipart headers in addition to per-file byte cap.
