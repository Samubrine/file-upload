# Authorization specification

## Matrix
All cells are enforced by Go on each request. A user with multiple roles gets owner permissions for owned files; otherwise evaluate their grant and listing independently.

| Action | Visitor | Authenticated unrelated, hidden file | Authenticated unrelated, listed file | Metadata-only recipient | Download recipient | Owner |
|---|---|---|---|---|---|---|
| Homepage | No | Listed files only | Yes | Listed files only | Listed files only | Listed files only |
| Discover this file | No | No | Filename + owner | Filename + owner | Filename + owner | Yes |
| Download bytes, any variant | No | No | No | No | Yes | Yes |
| List variants/size for this file | No | No | No | No | Yes | Yes |
| Rename/replace/delete | No | No | No | No | No | Yes |
| List/change recipients | No | No | No | No | No | Yes |
| Toggle homepage listing | No | No | No | No | No | Yes |

## Rules
view_metadata = owner OR listed OR grant.view_metadata OR grant.download.
download = owner OR grant.download.
manage = owner.
A grant is (file_id, recipient_id, view_metadata, download). Reject both false; download=true requires view_metadata=true. No self-grants, anonymous recipients, groups, reshare, or wildcard grants. Public listing is a boolean on the file, never a grant.

GET homepage includes only listed files, regardless of existing grants. GET shared includes only explicitly granted files. GET mine includes owned files. Detail DTO for a mere listed/metadata-only recipient contains only id, filename, owner_username. Download-authorized DTO may additionally expose current revision, size, MIME, available variants. Owner DTO additionally includes listing/grants controls. Never include owner's email, full name, birthday, or raw encrypted payload in listing DTOs.

Sharing uses exact normalized username. No user-directory search. Recipient resolution occurs only in owner grant mutation; return recipient-not-found without enumerating suggestions. Rate-limit this action. An owner may choose to reveal metadata to a recipient without download even when hidden from homepage.

## Unauthorized responses
Unauthenticated → 401. Unknown file OR hidden file outside the user's scope → 404. Discoverable file with insufficient permission for the requested action → 403. This applies to metadata, variants, content, and mutations. No early SQL lookup should leak private filenames in errors. Route UUID unpredictability never replaces authorization.

## Mutation behavior
Rename preserves listing/grants; owners see a disclosure reminder when listed. Changing listing to false removes homepage discovery but preserves explicit grants. Grant revocation blocks new requests; it cannot revoke plaintext already downloaded or stop an already-authorized transfer guaranteedly. Replacement always resets listing and deletes grants. New bytes must never inherit old-content permission implicitly.

## Concurrency
Mutations include current revision through If-Match; stale revision → 409 with no changes. Increment revision on rename, replace, listing changes, grant changes; metadata-only mutation does not re-encrypt unchanged file bytes, whose immutable content_revision remains separate. Update metadata payloads when filename changes. Download reads ACL and its ciphertext snapshot consistently; changes committed before its authorization snapshot must be respected. If deletion/revocation commits after download authorization, an in-flight transfer may finish; document this boundary.

No request-access messaging feature is included. Listed rows without a grant display “Download permission required” with no active download action.
