// Filesystem restriction configs (internal structures built from permission rules)

/**
 * Read restriction config using a "deny-only" pattern.
 *
 * Semantics:
 * - `undefined` = no restrictions (allow all reads)
 * - `{denyOnly: []}` = no restrictions (empty deny list = allow all reads)
 * - `{denyOnly: [...paths]}` = deny reads from these paths, allow all others
 *
 * This is maximally permissive by default - only explicitly denied paths are blocked.
 */
export interface FsReadDenyOnlyConfig {
  denyOnly: string[]
}

/**
 * Read restriction config using an "allow-only" pattern.
 *
 * Semantics:
 * - `{allowOnly: [], denyWithinAllow: []}` = maximally restrictive (deny ALL reads except system paths)
 * - `{allowOnly: [...paths], denyWithinAllow: [...]}` = allow reads only from these paths (plus system paths),
 *   with exceptions for denyWithinAllow
 *
 * This is maximally restrictive by default - only explicitly allowed paths are readable.
 * System paths required for sandbox operation are always included automatically.
 * Note: Empty `allowOnly` means only system paths are readable.
 */
export interface FsReadAllowOnlyConfig {
  allowOnly: string[]
  denyWithinAllow: string[]
}

/**
 * Union type for read restriction configurations.
 * Supports either deny-only (current default) or allow-only (for multi-tenant isolation).
 */
export type FsReadRestrictionConfig =
  | FsReadDenyOnlyConfig
  | FsReadAllowOnlyConfig

/**
 * Type guard to check if read config is deny-only mode
 */
export function isReadDenyOnlyConfig(
  config: FsReadRestrictionConfig,
): config is FsReadDenyOnlyConfig {
  return 'denyOnly' in config
}

/**
 * Type guard to check if read config is allow-only mode
 */
export function isReadAllowOnlyConfig(
  config: FsReadRestrictionConfig,
): config is FsReadAllowOnlyConfig {
  return 'allowOnly' in config
}

/**
 * Write restriction config using an "allow-only" pattern.
 *
 * Semantics:
 * - `undefined` = no restrictions (allow all writes)
 * - `{allowOnly: [], denyWithinAllow: []}` = maximally restrictive (deny ALL writes)
 * - `{allowOnly: [...paths], denyWithinAllow: [...]}` = allow writes only to these paths,
 *   with exceptions for denyWithinAllow
 *
 * This is maximally restrictive by default - only explicitly allowed paths are writable.
 * Note: Empty `allowOnly` means NO paths are writable (unlike read's empty denyOnly).
 */
export interface FsWriteRestrictionConfig {
  allowOnly: string[]
  denyWithinAllow: string[]
}

/**
 * Network restriction config (internal structure built from permission rules).
 *
 * This uses an "allow-only" pattern (like write restrictions):
 * - `allowedHosts` = hosts that are explicitly allowed
 * - `deniedHosts` = hosts that are explicitly denied (checked first, before allowedHosts)
 *
 * Semantics:
 * - `undefined` = maximally restrictive (deny all network)
 * - `{allowedHosts: [], deniedHosts: []}` = maximally restrictive (nothing allowed)
 * - `{allowedHosts: [...], deniedHosts: [...]}` = apply allow/deny rules
 *
 * Note: Empty `allowedHosts` means NO hosts are allowed (unlike read's empty denyOnly).
 */
export interface NetworkRestrictionConfig {
  allowedHosts?: string[]
  deniedHosts?: string[]
}

export type NetworkHostPattern = {
  host: string
  port: number | undefined
}

export type SandboxAskCallback = (
  params: NetworkHostPattern,
) => Promise<boolean>
