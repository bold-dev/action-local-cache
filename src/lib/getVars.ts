import path from 'path'

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

  const pathItems: PathItem[] = options.paths.map((pathStr) => {
    const targetPath = path.resolve(CWD, pathStr)

    // Create a safe cache path by using the relative path from CWD
    // This prevents issues with absolute paths creating nested directory structures
    const relativePath = path.relative(CWD, targetPath)
    const cachePath = path.join(cacheDir, relativePath)

    console.log(`DEBUG: pathStr = ${pathStr}`)
    console.log(`DEBUG: targetPath = ${targetPath}`)
    console.log(`DEBUG: relativePath = ${relativePath}`)
    console.log(`DEBUG: cachePath = ${cachePath}`)

    const { dir: targetDir } = path.parse(targetPath)

    return {
      cachePath,
      targetDir,
      targetPath,
    }
  })

  return {
    cacheDir,
    options,
    pathItems,
  }
}
