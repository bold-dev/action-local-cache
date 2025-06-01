import path from 'path'
import { globSync } from 'glob'

import * as core from '@actions/core'

const { GITHUB_REPOSITORY, RUNNER_TOOL_CACHE, LOCAL_CACHE_DIR } = process.env
const CWD = process.cwd()

export const STRATEGIES = ['copy-immutable', 'copy', 'move'] as const
export type Strategy = (typeof STRATEGIES)[number]

export type PathItem = {
  cachePath: string
  targetDir: string
  targetPath: string
}

type Vars = {
  cacheDir: string
  options: {
    key: string
    paths: string[]
    restoreKeys: string[]
    strategy: Strategy
    failOnCacheMiss: boolean
    saveAlways: boolean
  }
  pathItems: PathItem[]
  emptyGlobPatterns: string[]
}

/**
 * Check if a path contains glob patterns
 */
function isGlobPattern(pathStr: string): boolean {
  return (
    pathStr.includes('*') || pathStr.includes('?') || pathStr.includes('[') || pathStr.includes('{')
  )
}

/**
 * Expand glob patterns and return all matching paths
 */
function expandGlobPath(pathStr: string): string[] {
  try {
    const globPattern = path.resolve(CWD, pathStr)
    const matchedPaths = globSync(globPattern, {
      dot: true, // Include hidden files
      absolute: true,
      ignore: ['node_modules/**', '.git/**'], // Common ignore patterns
    })

    if (matchedPaths.length === 0) {
      console.warn(`Glob pattern "${pathStr}" matched no files`)
      // Return an empty array but don't throw - let the caller handle it
      return []
    }

    console.log(`Glob pattern "${pathStr}" matched ${matchedPaths.length} files`)
    return matchedPaths
  } catch (error) {
    console.error(`Error expanding glob pattern "${pathStr}":`, error)
    return []
  }
}

export const getVars = (): Vars => {
  // Use LOCAL_CACHE_DIR if provided, otherwise fall back to RUNNER_TOOL_CACHE
  const cacheRoot = LOCAL_CACHE_DIR || RUNNER_TOOL_CACHE

  if (!cacheRoot) {
    throw new TypeError(
      'Expected LOCAL_CACHE_DIR or RUNNER_TOOL_CACHE environment variable to be defined. Set LOCAL_CACHE_DIR to use a custom cache location.'
    )
  }

  if (!GITHUB_REPOSITORY) {
    throw new TypeError('Expected GITHUB_REPOSITORY environment variable to be defined.')
  }

  // Debug logging to see what values we're getting
  console.log(`DEBUG: LOCAL_CACHE_DIR = ${LOCAL_CACHE_DIR || 'not set'}`)
  console.log(`DEBUG: RUNNER_TOOL_CACHE = ${RUNNER_TOOL_CACHE}`)
  console.log(`DEBUG: Using cache root = ${cacheRoot}`)
  console.log(`DEBUG: GITHUB_REPOSITORY = ${GITHUB_REPOSITORY}`)
  console.log(`DEBUG: CWD = ${CWD}`)

  const options = {
    key: core.getInput('key') || 'no-key',
    paths: core.getMultilineInput('path'),
    restoreKeys: core.getMultilineInput('restore-keys'),
    strategy: core.getInput('strategy') as Strategy,
    failOnCacheMiss: core.getInput('fail-on-cache-miss').toLowerCase() === 'true',
    saveAlways: core.getInput('save-always').toLowerCase() === 'true',
  }

  if (options.paths.length === 0) {
    throw new TypeError('path is required but was not provided.')
  }

  if (!Object.values(STRATEGIES).includes(options.strategy)) {
    throw new TypeError(`Unknown strategy ${options.strategy}`)
  }

  const cacheDir = path.join(cacheRoot, GITHUB_REPOSITORY, options.key)
  console.log(`DEBUG: cacheDir = ${cacheDir}`)

  const pathItems: PathItem[] = []
  const emptyGlobPatterns: string[] = []

  // Process each path, expanding globs as needed
  for (const pathStr of options.paths) {
    console.log(`DEBUG: Processing path: ${pathStr}`)

    if (isGlobPattern(pathStr)) {
      // This is a glob pattern - expand it
      console.log(`DEBUG: Detected glob pattern: ${pathStr}`)
      const matchedPaths = expandGlobPath(pathStr)

      if (matchedPaths.length === 0) {
        // Track empty glob patterns for later validation
        emptyGlobPatterns.push(pathStr)
        console.log(
          `DEBUG: Glob pattern "${pathStr}" matched no files - will affect cache-hit calculation`
        )
      } else {
        for (const matchedPath of matchedPaths) {
          const relativePath = path.relative(CWD, matchedPath)
          const cachePath = path.join(cacheDir, relativePath)
          const { dir: targetDir } = path.parse(matchedPath)

          console.log(`DEBUG: Glob match - targetPath = ${matchedPath}`)
          console.log(`DEBUG: Glob match - relativePath = ${relativePath}`)
          console.log(`DEBUG: Glob match - cachePath = ${cachePath}`)

          pathItems.push({
            cachePath,
            targetDir,
            targetPath: matchedPath,
          })
        }
      }
    } else {
      // Regular path - existing logic
      const targetPath = path.resolve(CWD, pathStr)
      const relativePath = path.relative(CWD, targetPath)
      const cachePath = path.join(cacheDir, relativePath)

      console.log(`DEBUG: Regular path - pathStr = ${pathStr}`)
      console.log(`DEBUG: Regular path - targetPath = ${targetPath}`)
      console.log(`DEBUG: Regular path - relativePath = ${relativePath}`)
      console.log(`DEBUG: Regular path - cachePath = ${cachePath}`)

      const { dir: targetDir } = path.parse(targetPath)

      pathItems.push({
        cachePath,
        targetDir,
        targetPath,
      })
    }
  }

  console.log(`DEBUG: Total path items after expansion: ${pathItems.length}`)
  console.log(`DEBUG: Empty glob patterns: ${emptyGlobPatterns.length}`)
  if (emptyGlobPatterns.length > 0) {
    console.log(`DEBUG: Empty glob patterns were: ${emptyGlobPatterns.join(', ')}`)
  }

  return {
    cacheDir,
    options,
    pathItems,
    emptyGlobPatterns, // Include this for cache-hit calculation
  }
}
