import { setFailed, getInput } from '@actions/core'
import { mkdirP, mv, cp, rmRF } from '@actions/io'
import { exists } from '@actions/io/lib/io-util'

import { getVars, PathItem } from './lib/getVars'
import { isErrorLike } from './lib/isErrorLike'
import log from './lib/log'
import path from 'path'

/**
 * Process a single path item for caching based on the selected strategy
 */
async function processPathItem(
  pathItem: PathItem,
  cacheDir: string,
  strategy: string
): Promise<void> {
  const { targetPath, cachePath } = pathItem

  // Create parent directories for the cache path
  const cacheParentDir = path.dirname(cachePath)
  await mkdirP(cacheParentDir)

  switch (strategy) {
    case 'copy-immutable':
      if (await exists(cachePath)) {
        log.info(`Cache already exists for ${targetPath}, skipping`)
        return
      }
      await cp(targetPath, cachePath, { copySourceDirectory: true, recursive: true })
      break
    case 'copy':
      if (await exists(cachePath)) {
        await rmRF(cachePath)
      }
      await cp(targetPath, cachePath, { copySourceDirectory: true, recursive: true })
      break
    case 'move':
      await mv(targetPath, cachePath, { force: true })
      break
  }

  log.info(`Cache saved to ${cachePath} with ${strategy} strategy`)
}

async function post(): Promise<void> {
  try {
    const { cacheDir, pathItems, options } = getVars()

    // Check if we should save the cache
    const saveAlways = getInput('save-always').toLowerCase() === 'true'
    const strategy = getInput('strategy') || 'move'

    // Check job status - GitHub Actions sets this environment variable
    // If undefined, we assume success (for local testing or older GitHub Actions versions)
    const jobStatus = process.env.GITHUB_JOB_STATUS || 'success'
    const isJobSuccessful = jobStatus === 'success'

    // For move strategy, we always need to save to avoid losing the cache
    // For other strategies, respect the save-always setting and job status
    const shouldSave = strategy === 'move' || saveAlways || isJobSuccessful

    if (!shouldSave) {
      log.info('Skipping cache save due to job failure and save-always not enabled')
      return
    }

    if (strategy === 'move' && !saveAlways && !isJobSuccessful) {
      // This is purely for debugging purposes - explains why the cache is being saved
      log.info('Auto-saving cache due to move strategy (prevents cache loss)')
    }

    // Always save to the primary key, not any of the restore-keys
    log.info(`Saving cache with primary key: ${options.key} using ${strategy} strategy`)

    // Ensure the base cache directory exists
    await mkdirP(cacheDir)

    let processedCount = 0
    const totalPaths = pathItems.length

    for (const pathItem of pathItems) {
      try {
        if (await exists(pathItem.targetPath)) {
          await processPathItem(pathItem, cacheDir, options.strategy)
          processedCount++
        } else {
          log.info(`Path ${pathItem.targetPath} does not exist, skipping cache`)
        }
      } catch (itemError) {
        // Log but continue with other paths
        log.error(
          `Error processing ${pathItem.targetPath}: ${
            isErrorLike(itemError) ? itemError.message : 'unknown error'
          }`
        )
      }
    }

    log.info(
      `Cache saving complete. ${processedCount}/${totalPaths} paths were cached with key: ${options.key}`
    )
  } catch (error: unknown) {
    log.trace(error)
    setFailed(isErrorLike(error) ? error.message : `unknown error: ${error}`)
  }
}

void post()
