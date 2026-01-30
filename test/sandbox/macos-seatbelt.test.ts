import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
// Note: macOS allow-only mode handles system paths internally by allowing all reads
// then denying major user directories, so we don't need to include getDefaultReadPaths()
// in the tests.
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from '../../src/sandbox/sandbox-schemas.js'

/**
 * Tests for macOS Seatbelt read bypass vulnerability
 *
 * Issue: Files protected by read deny rules could be exfiltrated by moving them
 * to readable locations using the mv command. The rename() syscall was not blocked
 * by file-read* rules.
 *
 * Fix: Added file-write-unlink deny rules to block rename/move operations on:
 * 1. The denied files/directories themselves
 * 2. All ancestor directories (to prevent moving parent directories)
 *
 * These tests use the actual sandbox profile generation code to ensure real-world coverage.
 */

function skipIfNotMacOS(): boolean {
  return getPlatform() !== 'macos'
}

describe('macOS Seatbelt Read Bypass Prevention', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-test-' + Date.now())
  const TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied-dir')
  const TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_SECRET_CONTENT = 'SECRET_CREDENTIAL_DATA'
  const TEST_MOVED_FILE = join(TEST_BASE_DIR, 'moved-secret.txt')
  const TEST_MOVED_DIR = join(TEST_BASE_DIR, 'moved-denied-dir')

  // Additional test files for glob pattern testing
  const TEST_GLOB_DIR = join(TEST_BASE_DIR, 'glob-test')
  const TEST_GLOB_FILE1 = join(TEST_GLOB_DIR, 'secret1.txt')
  const TEST_GLOB_FILE2 = join(TEST_GLOB_DIR, 'secret2.log')
  const TEST_GLOB_MOVED = join(TEST_BASE_DIR, 'moved-glob.txt')

  beforeAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Create test directory structure
    mkdirSync(TEST_DENIED_DIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)

    // Create glob test files
    mkdirSync(TEST_GLOB_DIR, { recursive: true })
    writeFileSync(TEST_GLOB_FILE1, 'GLOB_SECRET_1')
    writeFileSync(TEST_GLOB_FILE2, 'GLOB_SECRET_2')
  })

  afterAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Clean up test directory
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('Literal Path - Direct File Move Prevention', () => {
    it('should block moving a read-denied file to a readable location', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config with literal path
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command using our production code
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_SECRET_FILE} ${TEST_MOVED_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify the file exists before test
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail with operation not permitted
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)
      expect(existsSync(TEST_MOVED_FILE)).toBe(false)
    })

    it('should still block reading the file (sanity check)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The read should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Should NOT see the secret content
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })
  })

  describe('Literal Path - Ancestor Directory Move Prevention', () => {
    it('should block moving an ancestor directory of a read-denied file', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_DENIED_DIR} ${TEST_MOVED_DIR}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify the directory exists before test
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)
      expect(existsSync(TEST_MOVED_DIR)).toBe(false)
    })

    it('should block moving the grandparent directory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Deny reading a specific file deep in the hierarchy
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_SECRET_FILE],
      }

      const movedBaseDir = join(tmpdir(), 'moved-base-' + Date.now())

      // Try to move the grandparent directory (TEST_BASE_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_BASE_DIR} ${movedBaseDir}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_BASE_DIR is an ancestor of TEST_SECRET_FILE
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_BASE_DIR)).toBe(true)
      expect(existsSync(movedBaseDir)).toBe(false)
    })
  })

  describe('Glob Pattern - File Move Prevention', () => {
    it('should block moving files matching a glob pattern (*.txt)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern that matches all .txt files in glob-test directory
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      // Try to move a .txt file that matches the pattern
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_FILE1} ${TEST_GLOB_MOVED}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify file exists
      expect(existsSync(TEST_GLOB_FILE1)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail for .txt file
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_GLOB_FILE1)).toBe(true)
      expect(existsSync(TEST_GLOB_MOVED)).toBe(false)
    })

    it('should still block reading files matching the glob pattern', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      // Try to read a file matching the glob
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_GLOB_FILE1}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The read should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Should NOT see the content
      expect(result.stdout).not.toContain('GLOB_SECRET_1')
    })

    it('should block moving the parent directory containing glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      const movedGlobDir = join(TEST_BASE_DIR, 'moved-glob-dir')

      // Try to move the parent directory
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_DIR} ${movedGlobDir}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_GLOB_DIR is an ancestor of the glob pattern
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_GLOB_DIR)).toBe(true)
      expect(existsSync(movedGlobDir)).toBe(false)
    })
  })

  describe('Glob Pattern - Recursive Patterns', () => {
    it('should block moving files matching a recursive glob pattern (**/*.txt)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create nested directory structure
      const nestedDir = join(TEST_GLOB_DIR, 'nested')
      const nestedFile = join(nestedDir, 'nested-secret.txt')
      mkdirSync(nestedDir, { recursive: true })
      writeFileSync(nestedFile, 'NESTED_SECRET')

      // Use recursive glob pattern
      const globPattern = join(TEST_GLOB_DIR, '**/*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      const movedNested = join(TEST_BASE_DIR, 'moved-nested.txt')

      // Try to move the nested file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${nestedFile} ${movedNested}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(nestedFile)).toBe(true)
      expect(existsSync(movedNested)).toBe(false)
    })
  })
})

describe('macOS Seatbelt Write Bypass Prevention', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-write-test-' + Date.now())
  const TEST_ALLOWED_DIR = join(TEST_BASE_DIR, 'allowed')
  const TEST_DENIED_DIR = join(TEST_ALLOWED_DIR, 'secrets')
  const TEST_DENIED_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_ORIGINAL_CONTENT = 'ORIGINAL_CONTENT'
  const TEST_MODIFIED_CONTENT = 'MODIFIED_CONTENT'

  // Additional test paths
  const TEST_RENAMED_DIR = join(TEST_BASE_DIR, 'renamed-secrets')

  // Glob pattern test paths
  const TEST_GLOB_DIR = join(TEST_ALLOWED_DIR, 'glob-test')
  const TEST_GLOB_SECRET1 = join(TEST_GLOB_DIR, 'secret1.txt')
  const TEST_GLOB_SECRET2 = join(TEST_GLOB_DIR, 'secret2.log')
  const TEST_GLOB_RENAMED = join(TEST_BASE_DIR, 'renamed-glob')

  beforeAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Create test directory structure
    mkdirSync(TEST_DENIED_DIR, { recursive: true })
    mkdirSync(TEST_GLOB_DIR, { recursive: true })

    // Create test files with original content
    writeFileSync(TEST_DENIED_FILE, TEST_ORIGINAL_CONTENT)
    writeFileSync(TEST_GLOB_SECRET1, TEST_ORIGINAL_CONTENT)
    writeFileSync(TEST_GLOB_SECRET2, TEST_ORIGINAL_CONTENT)
  })

  afterAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Clean up test directory
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('Literal Path - Direct Directory Move Prevention', () => {
    it('should block write bypass via directory rename (mv a c, write c/b, mv c a)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Allow writing to TEST_ALLOWED_DIR but deny TEST_DENIED_DIR
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_DIR],
      }

      // Step 1: Try to rename the denied directory
      const mvCommand1 = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_DENIED_DIR} ${TEST_RENAMED_DIR}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result1 = spawnSync(mvCommand1, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result1.status).not.toBe(0)
      const output1 = (result1.stderr || '').toLowerCase()
      expect(output1).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)
      expect(existsSync(TEST_RENAMED_DIR)).toBe(false)
    })

    it('should still block direct writes to denied paths (sanity check)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_DIR],
      }

      // Try to write directly to the denied file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_MODIFIED_CONTENT}" > ${TEST_DENIED_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The write should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT modified
      const content = readFileSync(TEST_DENIED_FILE, 'utf8')
      expect(content).toBe(TEST_ORIGINAL_CONTENT)
    })
  })

  describe('Literal Path - Ancestor Directory Move Prevention', () => {
    it('should block moving an ancestor directory of a write-denied path', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const movedAllowedDir = join(TEST_BASE_DIR, 'moved-allowed')

      // Try to move the parent directory (TEST_ALLOWED_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_ALLOWED_DIR} ${movedAllowedDir}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_ALLOWED_DIR is an ancestor
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_ALLOWED_DIR)).toBe(true)
      expect(existsSync(movedAllowedDir)).toBe(false)
    })

    it('should block moving the grandparent directory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const movedBaseDir = join(tmpdir(), 'moved-write-base-' + Date.now())

      // Try to move the grandparent directory (TEST_BASE_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_BASE_DIR} ${movedBaseDir}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_BASE_DIR is an ancestor
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_BASE_DIR)).toBe(true)
      expect(existsSync(movedBaseDir)).toBe(false)
    })
  })

  describe('Glob Pattern - File Move Prevention', () => {
    it('should block write bypass via moving glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Allow writing to TEST_ALLOWED_DIR but deny *.txt files in glob-test
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to move a .txt file
      const mvCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_SECRET1} ${join(TEST_BASE_DIR, 'moved-secret.txt')}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(mvCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_GLOB_SECRET1)).toBe(true)
    })

    it('should still block direct writes to glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to write to a glob-matched file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_MODIFIED_CONTENT}" > ${TEST_GLOB_SECRET1}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The write should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT modified
      const content = readFileSync(TEST_GLOB_SECRET1, 'utf8')
      expect(content).toBe(TEST_ORIGINAL_CONTENT)
    })

    it('should block moving the parent directory containing glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to move the parent directory
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_DIR} ${TEST_GLOB_RENAMED}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_GLOB_DIR)).toBe(true)
      expect(existsSync(TEST_GLOB_RENAMED)).toBe(false)
    })
  })

  describe('Glob Pattern - Recursive Patterns', () => {
    it('should block moving files matching a recursive glob pattern (**/*.txt)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create nested directory structure
      const nestedDir = join(TEST_GLOB_DIR, 'nested')
      const nestedFile = join(nestedDir, 'nested-secret.txt')
      mkdirSync(nestedDir, { recursive: true })
      writeFileSync(nestedFile, TEST_ORIGINAL_CONTENT)

      // Use recursive glob pattern
      const globPattern = join(TEST_GLOB_DIR, '**/*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      const movedNested = join(TEST_BASE_DIR, 'moved-nested.txt')

      // Try to move the nested file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${nestedFile} ${movedNested}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(nestedFile)).toBe(true)
      expect(existsSync(movedNested)).toBe(false)
    })
  })
})

describe('macOS Seatbelt Process Enumeration', () => {
  it('should allow enumerating all process IDs (kern.proc.all sysctl)', () => {
    if (skipIfNotMacOS()) {
      return
    }

    // This tests that psutil.pids() and similar process enumeration works.
    // The kern.proc.all sysctl is used by psutil to list all PIDs on the system.
    // Use case: IPython kernel shutdown needs to enumerate child processes.
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'ps -axo pid=',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // The command should succeed
    expect(result.status).toBe(0)

    // Should return a list of PIDs (at least the current process)
    const pids = result.stdout
      .trim()
      .split('\n')
      .filter(line => line.trim())
    expect(pids.length).toBeGreaterThan(0)

    // Each line should be a valid PID (numeric)
    for (const pid of pids) {
      expect(parseInt(pid.trim(), 10)).toBeGreaterThan(0)
    }
  })
})

/**
 * Tests for macOS Seatbelt allow-only read mode
 *
 * These tests verify that the allowRead mode works correctly on macOS,
 * allowing reads only from specified paths (plus system paths) while
 * blocking reads from all other locations.
 */
describe('macOS Seatbelt Allow-Only Read Mode', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-allow-read-' + Date.now())
  const TENANT_A_DIR = join(TEST_BASE_DIR, 'tenant-a')
  const TENANT_B_DIR = join(TEST_BASE_DIR, 'tenant-b')
  const SECRETS_DIR = join(TENANT_A_DIR, '.secrets')

  const TENANT_A_DATA = 'TENANT_A_DATA_CONTENT'
  const TENANT_B_DATA = 'TENANT_B_DATA_CONTENT'
  const SECRET_DATA = 'SECRET_API_KEY_12345'

  beforeAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Create test directory structure
    mkdirSync(TENANT_A_DIR, { recursive: true })
    mkdirSync(TENANT_B_DIR, { recursive: true })
    mkdirSync(SECRETS_DIR, { recursive: true })

    // Create test files
    writeFileSync(join(TENANT_A_DIR, 'data.txt'), TENANT_A_DATA)
    writeFileSync(join(TENANT_B_DIR, 'data.txt'), TENANT_B_DATA)
    writeFileSync(join(SECRETS_DIR, 'api-key.txt'), SECRET_DATA)
  })

  afterAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Clean up test directory
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('Allow-Only Read - Basic Functionality', () => {
    it('should allow reading from explicitly allowed path', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${join(TENANT_A_DIR, 'data.txt')}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain(TENANT_A_DATA)
    })

    it('should block reading from path outside allowlist', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${join(TENANT_B_DIR, 'data.txt')}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - tenant B's directory is not in allowOnly
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')
      expect(result.stdout).not.toContain(TENANT_B_DATA)
    })

    it('should block reading from denyWithinAllow path', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [SECRETS_DIR],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${join(SECRETS_DIR, 'api-key.txt')}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - secrets are in denyWithinAllow
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')
      expect(result.stdout).not.toContain(SECRET_DATA)
    })

    it('should allow system commands to work (system paths readable)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [],
      }

      // ls command requires reading /bin or /usr/bin
      // Use ls /bin to verify system paths are readable
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: 'ls /bin | head -5',
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      // Should see typical /bin entries like bash, cat, ls, etc.
      expect(result.stdout).toMatch(/bash|cat|ls|sh/i)
    })

    it('should allow echo and basic shell operations', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: 'echo "Hello from sandbox"',
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('Hello from sandbox')
    })
  })

  describe('Allow-Only Read - Move Prevention', () => {
    it('should block moving files from denyWithinAllow to readable location', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [SECRETS_DIR],
      }

      const movedFile = join(TENANT_A_DIR, 'moved-secret.txt')

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${join(SECRETS_DIR, 'api-key.txt')} ${movedFile}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - cannot move denied files
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify file was NOT moved
      expect(existsSync(join(SECRETS_DIR, 'api-key.txt'))).toBe(true)
      expect(existsSync(movedFile)).toBe(false)
    })

    it('should block moving denyWithinAllow directory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [SECRETS_DIR],
      }

      const movedDir = join(TENANT_A_DIR, 'moved-secrets')

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${SECRETS_DIR} ${movedDir}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - cannot move denied directories
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify directory was NOT moved
      expect(existsSync(SECRETS_DIR)).toBe(true)
      expect(existsSync(movedDir)).toBe(false)
    })
  })

  describe('Allow-Only Read with Write Restrictions', () => {
    it('should enforce both read and write restrictions simultaneously', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [SECRETS_DIR],
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [SECRETS_DIR],
      }

      // Should be able to read from allowed path
      const readCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${join(TENANT_A_DIR, 'data.txt')}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig,
      })

      const readResult = spawnSync(readCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(readResult.status).toBe(0)
      expect(readResult.stdout).toContain(TENANT_A_DATA)

      // Should be able to write to allowed path
      const testFile = join(TENANT_A_DIR, 'write-test.txt')
      const writeCommand = wrapCommandWithSandboxMacOS({
        command: `echo "test content" > ${testFile}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig,
      })

      const writeResult = spawnSync(writeCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(writeResult.status).toBe(0)
      expect(existsSync(testFile)).toBe(true)

      // Should NOT be able to read from tenant B
      const blockedReadCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${join(TENANT_B_DIR, 'data.txt')}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig,
      })

      const blockedReadResult = spawnSync(blockedReadCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(blockedReadResult.status).not.toBe(0)
      expect(blockedReadResult.stdout).not.toContain(TENANT_B_DATA)

      // Should NOT be able to write to tenant B
      const blockedWriteCommand = wrapCommandWithSandboxMacOS({
        command: `echo "hacked" > ${join(TENANT_B_DIR, 'hacked.txt')}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig,
      })

      const blockedWriteResult = spawnSync(blockedWriteCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(blockedWriteResult.status).not.toBe(0)
      expect(existsSync(join(TENANT_B_DIR, 'hacked.txt'))).toBe(false)

      // Cleanup
      if (existsSync(testFile)) {
        rmSync(testFile)
      }
    })

    it('should work with unrestricted network (filesystem-only sandboxing)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [],
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [],
      }

      // Network should work (no restriction)
      const networkCommand = wrapCommandWithSandboxMacOS({
        command: 'curl -s --max-time 5 http://example.com',
        needsNetworkRestriction: false, // No network restriction
        readConfig,
        writeConfig,
      })

      const networkResult = spawnSync(networkCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      expect(networkResult.status).toBe(0)
      expect(networkResult.stdout).toContain('Example Domain')

      // But filesystem restrictions should still apply
      const blockedReadCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${join(TENANT_B_DIR, 'data.txt')}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig,
      })

      const blockedReadResult = spawnSync(blockedReadCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(blockedReadResult.status).not.toBe(0)
      expect(blockedReadResult.stdout).not.toContain(TENANT_B_DATA)
    })
  })

  describe('Allow-Only Read - Glob Patterns', () => {
    it('should support glob patterns in denyWithinAllow', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create additional test files
      const secretTxt = join(TENANT_A_DIR, 'secret.txt')
      const normalLog = join(TENANT_A_DIR, 'normal.log')
      writeFileSync(secretTxt, 'SECRET_TXT_CONTENT')
      writeFileSync(normalLog, 'NORMAL_LOG_CONTENT')

      // macOS allow-only mode handles system paths internally
      const readConfig: FsReadRestrictionConfig = {
        allowOnly: [TENANT_A_DIR],
        denyWithinAllow: [join(TENANT_A_DIR, '*.txt')], // Block all .txt files
      }

      // Should block reading .txt file
      const txtCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${secretTxt}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const txtResult = spawnSync(txtCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(txtResult.status).not.toBe(0)
      expect(txtResult.stdout).not.toContain('SECRET_TXT_CONTENT')

      // Should allow reading .log file (not in glob pattern)
      const logCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${normalLog}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const logResult = spawnSync(logCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(logResult.status).toBe(0)
      expect(logResult.stdout).toContain('NORMAL_LOG_CONTENT')

      // Cleanup
      rmSync(secretTxt)
      rmSync(normalLog)
    })
  })
})
