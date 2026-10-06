export interface Profile {
  full_name: string;
  username: string;
  email: string;
  birthday: string | null;
}

export interface Session {
  csrf_token: string;
  expires_at: string;
  user: Profile;
}

export interface Metadata {
  id: string;
  filename: string;
  owner_username: string;
}

export interface DownloadFile {
  id: string;
  filename: string;
  owner_username: string;
  revision: number;
  content_revision: number;
  size_bytes: number;
  mime: string;
  variants: string[];
}

export interface OwnerFile {
  id: string;
  filename: string;
  owner_username: string;
  revision: number;
  content_revision: number;
  size_bytes: number;
  mime: string;
  variants: string[];
  listed: boolean;
}

export type FileDetail = Metadata | DownloadFile | OwnerFile;

export function isOwnerFile(file: FileDetail): file is OwnerFile {
  return 'listed' in file;
}

export function isDownloadFile(file: FileDetail): file is DownloadFile {
  return 'variants' in file && !('listed' in file);
}

export function isMetadataFile(file: FileDetail): file is Metadata {
  return !('variants' in file);
}

export interface Grant {
  recipient_username: string;
  view_metadata: boolean;
  download: boolean;
}

export interface GrantSet {
  view_metadata: boolean;
  download: boolean;
}

export interface Quota {
  logical_used_bytes: number;
  logical_limit_bytes: number;
  physical_used_bytes: number;
  physical_limit_bytes: number;
  file_count: number;
  file_count_limit: number;
}

export interface Notice {
  version: string;
  text: string;
  project_contact: string;
}

export interface Registry {
  default: string;
  variants: string[];
}

export interface ErrorResponse {
  code: string;
  message: string;
  request_id: string;
}

export interface MetadataPage {
  items: Metadata[];
  offset: number;
  limit: number;
  total: number;
}

export interface OwnerPage {
  items: OwnerFile[];
  offset: number;
  limit: number;
  total: number;
}

export interface SharedPage {
  items: FileDetail[];
  offset: number;
  limit: number;
  total: number;
}

