Local Cache Action
A GitHub Action to save and restore files across job runs directly in the runner's file system.
Features

Cache files and directories locally on the runner
Support for multiline paths
Restore-keys functionality for fallback caching
Multiple caching strategies
Cross-platform compatibility (Linux, Windows)
Separate restore and save actions for flexible workflows
Option to fail workflow if cache is not found
Option to save cache even when workflow fails

How It Works
This action saves and restores cached files to the local file system of the runner using the standard RUNNER_TOOL_CACHE environment variable that GitHub Actions provides. This allows for fast caching without external transfers, making it ideal for self-hosted runners.
Usage
Basic Usage (Combined Action)
yaml- name: Cache dependencies
  uses: bold-dev/action-local-cache@2
  with:
    path: |
      ./node_modules
      ./packages/*/node_modules
    key: ${{ runner.os }}-modules-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      ${{ runner.os }}-modules-
Separate Restore and Save Actions
For more flexibility, you can use the separate restore and save actions:
Restore
yaml- name: Restore dependencies from cache
  id: cache-restore
  uses: bold-dev/action-local-cache/restore@2
  with:
    path: |
      ./node_modules
      ./packages/*/node_modules
    key: ${{ runner.os }}-modules-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      ${{ runner.os }}-modules-
Save (after your build steps)
yaml- name: Save dependencies to cache
  uses: bold-dev/action-local-cache/save@2
  with:
    path: |
      ./node_modules
      ./packages/*/node_modules
    key: ${{ runner.os }}-modules-${{ hashFiles('**/package-lock.json') }}
Inputs
path
Required File path(s) to cache/restore. Can be a single path or multiline paths.
key
Required An explicit key for identifying the cache.
restore-keys
Optional An ordered list of keys to use for restoring the cache if no cache hit occurred for key.
strategy
Optional Caching mechanism to be used. Valid values:

move (default): Move files between cache and target locations
copy: Copy files, leaving originals in place
copy-immutable: Copy files, but won't overwrite existing cache files

fail-on-cache-miss
Optional If set to true, the workflow will fail if no valid cache is found. Default: false
save-always
Optional If set to true, the cache will be saved even if the workflow fails. Default: false.
Note: This option is only used with the combined action, not with the separate save action.
Outputs
cache-hit
A boolean value indicating if the cache was found and restored.
restored-key
The key that was used to restore the cache (can be primary key or one of the restore-keys).
Example Workflows
Using the Combined Action
yaml- name: Cache NPM packages
  id: npm-cache
  uses: bold-dev/action-local-cache@2
  with:
    path: |
      ./node_modules
      ./packages/*/node_modules
    key: npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      npm-${{ runner.os }}-
    # Save cache even if the workflow fails
    save-always: true

- name: Install dependencies
  if: steps.npm-cache.outputs.cache-hit != 'true'
  run: npm ci
Using Separate Restore/Save Actions
yaml# Restore cache at the beginning
- name: Restore NPM packages
  id: npm-cache
  uses: bold-dev/action-local-cache/restore@2
  with:
    path: |
      ./node_modules
      ./packages/*/node_modules
    key: npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      npm-${{ runner.os }}-
    # Fail the workflow if no cache is found
    fail-on-cache-miss: true

# Install dependencies if no cache hit
- name: Install dependencies
  if: steps.npm-cache.outputs.cache-hit != 'true'
  run: npm ci

# Run build steps
- name: Build
  run: npm run build

# Save cache at the end
- name: Save NPM packages
  uses: bold-dev/action-local-cache/save@2
  with:
    path: |
      ./node_modules
      ./packages/*/node_modules
    key: npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
Combining Options for Different Use Cases
Always Save Cache, Regardless of Build Success
yaml- name: Cache Build Artifacts
  uses: bold-dev/action-local-cache@2
  with:
    path: ./build
    key: build-${{ github.sha }}
    save-always: true
Require Cache Hit (Useful for Deployment Jobs)
yaml- name: Restore Build Artifacts
  id: build-cache
  uses: bold-dev/action-local-cache/restore@2
  with:
    path: ./build
    key: build-${{ github.sha }}
    fail-on-cache-miss: true
Self-Hosted Runners
When using self-hosted runners, ensure the RUNNER_TOOL_CACHE environment variable is set to a writeable directory. This is typically set automatically when setting up a GitHub Actions runner, but you might need to configure it manually in some environments.
Why Use Local Cache?

Works well with self-hosted runners
Avoids network transfer times for caching
Simple directory-based caching mechanism
Flexible caching strategies
Similar interface to GitHub's native cache action