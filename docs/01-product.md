# Product requirements

## Vocabulary
Private: not discoverable by unrelated users. Listed: filename and owner username discoverable to all authenticated users. Visible to recipient: metadata is discoverable through an explicit grant. Downloadable: server may send decrypted bytes. These are independent concepts; a listed file is not anonymous in the legal sense. Variant: independently encrypted copy, not fourteen separate files in the UI. Revision: current file content generation.

## Requirements
| ID | Requirement and acceptance condition |
|---|---|
| AUTH-01 | Register with full name, unique username, unique email, password, optional birthday; no other personal profile fields. |
| AUTH-02 | Login using username/password; generic login failures; logout invalidates server session. |
| AUTH-03 | All application data routes require a valid session. No password recovery or email delivery. |
| PROF-01 | Owner can read/update their own profile and change password with current password; username is immutable. |
| PROF-02 | Account deletion with password confirmation deletes owned files, own profile copies, sessions, and incoming/outgoing grants. |
| FILE-01 | Upload ID-card images, images, PDF/DOC/DOCX/XLS/XLSX, and video under validation/limits. ID-card label is optional and adds no extracted ID fields. |
| FILE-02 | Store fourteen independent encrypted copies of each file content, file metadata, and profile payload; atomic completeness required. |
| FILE-03 | Owner downloads byte-identical plaintext using any registered variant; default AES-256-CTR. |
| FILE-04 | Owner renames display filename while preserving extension and content; never treat filename as a server path. |
| FILE-05 | Owner replaces file; atomically switch to a fresh revision with fourteen variants and no old grants/public listing. |
| FILE-06 | Owner deletes file and all encrypted variants/grants. No trash or version history. |
| DISC-01 | Homepage lists only owner-opted-in files for authenticated users; row exposes filename, owner username, and opaque routing ID only. |
| DISC-02 | No content previews, thumbnails, document conversions, inline playback, or content-byte requests for a listing. |
| SHARE-01 | Owner grants a registered username metadata visibility only or metadata plus download. |
| SHARE-02 | Owner can revoke; recipients cannot rename, replace, delete, change grants, or list a file publicly. |
| SHARE-03 | Download permission does not depend on public listing; listing alone never permits download. |
| CRYPTO-01 | Registry is exactly fourteen supported variants; CBC uses PKCS#7; every envelope has independent key material and integrity protection. |
| BENCH-01 | Repeat authorized downloads across variants and measure server decryption plus client full-download time separately. |
| BENCH-02 | Compare cipher-only size, envelope size, correctness, throughput, and repeated runtime using synthetic fixtures. |
| PRIV-01 | Encrypt profile/file metadata at rest; no secrets or private fields in logs; disclose public filename/username exposure. |
| PRIV-02 | Privacy notice describes fields, purpose, storage, sharing, deletion, and educational crypto limitations; no compliance badge. |
| UX-01 | Responsive keyboard-accessible interface with explicit permission/visibility labels and predictable loading/error states. |
| QUAL-01 | Every requirement has traceable evidence; report limitations and measured results honestly. |

## Input defaults
Full name: trim, 1–100 Unicode characters. Username: ASCII [a-z0-9_], 3–32 characters; trim/lowercase before registration and login, immutable thereafter. Email: required, at most 254 characters, validate syntax, trim/lowercase as a documented project identity convention; uniqueness does not verify email ownership. Birthday: optional ISO date, valid nonfuture date, no age gate. Password: 12–128 Unicode code points, at most 512 UTF-8 bytes; preserve spaces/case, no silent trimming or truncation. Password policy is a project default, not a statement of legal requirements.

## File limits
Images/documents: 20 MiB each. Video: 50 MiB each. Logical quota: 100 MiB and 100 files per user. Physical live-payload quota: 2 GiB/user, 10 GiB/instance. Calculate actual fourteen-envelope footprint before commit. These are classroom defaults rather than universal industry standards. Replace counts old revision as credited within transaction; reject if resulting logical/physical quota is exceeded. Operational headroom for transactions/WAL/backups is additional to quotas.

Allowlist: .jpg/.jpeg/.png/.webp (image); .pdf; .doc/.docx; .xls/.xlsx; .mp4/.webm/.mov (video). No SVG, HTML, executables, archives, audio-only formats, folders, or batch uploads. One file/request. Do not imply stored files have been malware scanned.

## Non-goals
Content viewing, video streaming, online editing, search inside files, OCR, public/anonymous sharing links, admin access to user content, notifications/email, MFA, password recovery, resumable uploads, multi-instance deployment, virus-scanning service, retained revisions, user activity feeds, production compliance certification.
