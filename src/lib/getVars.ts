import path from 'path'

import * as core from '@actions/core'

const { GITHUB_REPOSITORY, RUNNER_TOOL_CACHE } = process.env
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
  if (!RUNNER_TOOL_CACHE) {
    throw new TypeError(
      'Expected RUNNER_TOOL_CACHE environment variable to be defined. This is typically set by GitHub Actions, but may need to be configured in self-hosted runners.'
    )
  }

  if (!GITHUB_REPOSITORY) {
    throw new TypeError('Expected GITHUB_REPOSITORY environment variable to be defined.')
  }

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

  const cacheDir = path.join(RUNNER_TOOL_CACHE, GITHUB_REPOSITORY, options.key)

  const pathItems: PathItem[] = options.paths.map((pathStr) => {
    const targetPath = path.resolve(CWD, pathStr)
    const cachePath = path.join(cacheDir, pathStr)
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
