import { setFailed, setOutput } from '@actions/core'
import { mkdirP, mv, cp } from '@actions/io/'
import { exists } from '@actions/io/lib/io-util'
import * as fs from 'fs'
import * as path from 'path'

import { getVars, PathItem } from './lib/getVars'
import { isErrorLike } from './lib/isErrorLike'
import log from './lib/log'

/**
 * Process a single path item based on the selected strategy
 */
async function processPathItem(pathItem: PathItem, strategy: string): Promise<boolean> {
  const { cachePath, targetDir, targetPath } = pathItem

  if (await exists(cachePath)) {
    await mkdirP(targetDir)

    switch (strategy) {
      case 'copy-immutable':
      case 'copy':
        await cp(cachePath, targetPath, {
          copySourceDirectory: false,
          recursive: true,
        })
        break
      case 'move':
        await mv(cachePath, targetPath, { force: true })
        break
    }

    log.info(`Cache found and restored to ${targetPath} with ${strategy} strategy`)
    return true
  } else {
    log.info(`Skipping: cache not found for ${targetPath}.`)
    return false
  }
}

/**
 * Find existing cache directories by key prefix
 */
async function findMatchingCaches(baseCacheDir: string, keyPrefix: string): Promise<string[]> {
  try {
    const repoDir = path.dirname(baseCacheDir)
    if (!(await exists(repoDir))) {
      return []
    }

    const dirents = await fs.promises.readdir(repoDir, { withFileTypes: true })
    const matches = dirents
      .filter((dirent) => dirent.isDirectory() && dirent.name.startsWith(keyPrefix))
      .map((dirent) => dirent.name)
      .sort((a, b) => {
        // Sort by name in descending order (reverse alphabetical)
        // This is to prioritize newer versions (v2 over v1, etc.)
        return b.localeCompare(a)
      })

    return matches
  } catch (error) {
    log.warn(
      `Error finding matching caches: ${isErrorLike(error) ? error.message : 'unknown error'}`
    )
    return []
  }
}

/**
 * Find the first valid cache key based on primary key and restore-keys
 */
async function findValidCacheKey(
  baseCacheDir: string,
  primaryKey: string,
  restoreKeys: string[]
): Promise<string | null> {
  // First, check the primary key
  const primaryKeyDir = path.join(baseCacheDir, primaryKey)
  if (await exists(primaryKeyDir)) {
    return primaryKey
  }

  // If primary key not found, try the restore-keys
  for (const restoreKey of restoreKeys) {
    // For each restore key (prefix), find all matching cache directories
    const matches = await findMatchingCaches(baseCacheDir, restoreKey)

    // Return the first match (if any)
    if (matches.length > 0) {
      return matches[0]
    }
  }

  return null
}

async function main(): Promise<void> {
  try {
    const { pathItems, options } = getVars()
    const { GITHUB_REPOSITORY, RUNNER_TOOL_CACHE } = process.env

    if (!RUNNER_TOOL_CACHE || !GITHUB_REPOSITORY) {
      throw new Error('Required environment variables are missing')
    }

    const repoBaseCacheDir = path.join(RUNNER_TOOL_CACHE, GITHUB_REPOSITORY)

    // Find a valid cache key to use
    const validKey = await findValidCacheKey(repoBaseCacheDir, options.key, options.restoreKeys)

    if (!validKey) {
      log.info(`No valid cache key found for key: ${options.key} or restore-keys`)
      setOutput('cache-hit', false)
      setOutput('restored-key', '')

      // If fail-on-cache-miss is true, fail the workflow
      if (options.failOnCacheMiss) {
        throw new Error(
          `Cache miss: No valid cache found for key '${options.key}' or any restore keys. The workflow has been configured to fail on cache miss.`
        )
      }

      return
    }

    // Adjust the pathItems with the valid key
    const adjustedPathItems = pathItems.map((item) => {
      const originalRelativePath = path.relative(
        path.join(repoBaseCacheDir, options.key),
        item.cachePath
      )

      return {
        ...item,
        cachePath: path.join(repoBaseCacheDir, validKey, originalRelativePath),
      }
    })

    let cacheCount = 0
    let totalPaths = adjustedPathItems.length

    for (const pathItem of adjustedPathItems) {
      const result = await processPathItem(pathItem, options.strategy)
      if (result) cacheCount++
    }

    // Only consider it a cache hit if at least one path was actually restored
    const cacheHit = cacheCount > 0

    // Set outputs based on actual restoration results
    setOutput('cache-hit', cacheHit)

    if (cacheHit) {
      const isPrimaryKey = validKey === options.key
      setOutput('restored-key', validKey)
      log.info(
        `Cache restoration complete. ${cacheCount}/${totalPaths} paths were restored using key: ${validKey}`
      )
      log.info(`Primary key hit: ${isPrimaryKey}`)
    } else {
      setOutput('restored-key', '')
      log.info(
        `Cache key '${validKey}' found but no files were restored. This may indicate an empty or corrupted cache.`
      )

      // If fail-on-cache-miss is true and no files were actually restored, fail the workflow
      if (options.failOnCacheMiss) {
        throw new Error(
          `Cache miss: Cache key '${validKey}' found but no files could be restored. The workflow has been configured to fail on cache miss.`
        )
      }
    }
  } catch (error: unknown) {
    console.trace(error)
    setFailed(isErrorLike(error) ? error.message : `unknown error: ${error}`)
  }
}

void main()
