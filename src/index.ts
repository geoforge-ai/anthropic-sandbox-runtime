// Library exports
export { SandboxManager } from './sandbox/sandbox-manager.js'
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js'

// Configuration types and schemas
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  IgnoreViolationsConfig,
} from './sandbox/sandbox-config.js'

export {
  SandboxRuntimeConfigSchema,
  NetworkConfigSchema,
  FilesystemConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
} from './sandbox/sandbox-config.js'

// Schema types and utilities
export type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsReadDenyOnlyConfig,
  FsReadAllowOnlyConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
  NetworkHostPattern,
} from './sandbox/sandbox-schemas.js'

export {
  isReadDenyOnlyConfig,
  isReadAllowOnlyConfig,
} from './sandbox/sandbox-schemas.js'

// Platform-specific utilities
export type { SandboxViolationEvent } from './sandbox/macos-sandbox-utils.js'
export { type SandboxDependencyCheck } from './sandbox/linux-sandbox-utils.js'

// Utility functions
export {
  getDefaultWritePaths,
  getDefaultReadPaths,
} from './sandbox/sandbox-utils.js'

// Platform utilities
export { getWslVersion } from './utils/platform.js'
export type { Platform } from './utils/platform.js'
