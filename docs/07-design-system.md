# Design system and interaction specification

## Direction
Quiet, professional file manager. English UI, light theme, restrained slate/blue palette, no gradients, decorative illustrations, or content thumbnails. Working name CipherVault. The name is not a security guarantee. Sidebar desktop; compact top navigation mobile. Use a consistent table/list rather than file-content cards.

## Tokens
contracts/design-tokens.json is the canonical numeric/color source. System sans font; monospace for variant IDs and timing data. Body 16px/24px; secondary 14px/20px; page title 28px/36px, weight 600. Spacing multiples of 4px; main gap 24px; card padding 24px desktop/16px mobile. Radius 8px components/12px panels. Borders 1px. No shadow unless separating a modal. Max content width 1200px; mobile padding 16px. Responsive breakpoints 640px, 1024px. Minimum action target 44px; input height 44px.

## Components and states
Buttons: primary blue, secondary bordered, danger red, disabled with reason. Inputs: visible labels, helper/error text linked with aria-describedby; no placeholder-only labels. Password has reveal toggle and no paste restriction. Table/list rows: filename text + generic extension icon, owner username, context-specific controls; no fetched image. Badges: Private, Listed, Metadata access, Download access. Never label a listed file “public download.” File owner cards may show size/type; homepage metadata-only rows may not.

Upload panel: file picker/drop target, allowed formats/size helper, optional “ID-card image” category, upload progress, encrypted-copy creation state, committed success. Do not promise percentage encryption progress if server exposes no progress API; use indeterminate “Creating encrypted copies…” after request upload progress. No optimistic file creation or permission changes; wait for server success.

Share dialog: exact username input, access selection “Filename and owner only” / “Filename, owner and download”; recipient list and revoke. Separate toggle for “List on homepage.” Confirmation on listing, replacement, deletion, account deletion; revoke is immediate with clear success notification and in-flight transfer limitation in help text. Replacement warns it hides file and removes all grants.

Cipher selector: default hidden behind “Encryption comparison” details; list fourteen grouped variants for owner/download recipient only. DES/RC4 labelled “Legacy / educational”. No security rankings derived from download speed. Cipher diagnostics page shows ciphertext lengths and synthetic benchmark results, not decrypted content or stored ciphertext previews.

## Pages
/auth/register: notice link, full name, username, email, password, optional birthday, acknowledgement; server validation inline.
/auth/login: username/password, generic failure, no forgot-password link.
/home: listed filename/owner rows; search of already authorized metadata and pagination; no download unless separately granted.
/my-files: owned list, upload, rename, replace, delete, sharing/listing controls.
/shared: explicit grants, badge for metadata/download, download only where authorized.
/files/:id: metadata detail with DTO appropriate to permission, actions consistent with grant.
/account: private profile, optional birthday, update email/name/birthday, change password, export own profile, delete account; username read-only.
/comparison: educational description and exported synthetic results; no server-driven arbitrary benchmark work launched by normal users.

## All pages
Loading skeleton with no fake content; empty state explains one relevant action; recoverable error with Retry; expired session returns login with safe internal return URL; success aria-live polite; validation focus first invalid field; destructive error does not discard current inputs. No console/stack-trace disclosure. Search results are scoped before filtering. Homepage never suggests a hidden file exists.

## Accessibility
Target WCAG 2.2 AA for implemented interface; verify contrast, keyboard order, focus-visible 2px blue outline with offset, dialog focus trap/restoration, accessible names, status announcements, zoom/reflow at 320 CSS pixels, reduced motion. Meaning uses labels/icons as well as color. Tables have column headers; mobile rows preserve labels and action semantics. Font at least 14px for secondary copy. Respect prefers-reduced-motion; transitions max 120ms, no required animation.
