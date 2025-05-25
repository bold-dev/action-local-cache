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
This action saves and restores cached files to the local file system of the runner. By default, it uses the standard RUNNER_TOOL_CACHE environment variable that GitHub Actions provides. However, you can override this by setting the LOCAL_CACHE_DIR environment variable to specify a custom cache location.

Environment Variables
LOCAL_CACHE_DIR (Optional)
Set this environment variable to use a custom cache directory instead of the default RUNNER_TOOL_CACHE. This is useful when you want to store caches in a specific location on self-hosted runners.

Example:

yaml
env:
  LOCAL_CACHE_DIR: "/tmp/cache"
If not set, the action will use the default RUNNER_TOOL_CACHE location.

Move Strategy (Default)
Restore: Files are moved from cache to target location
Save: Files are moved from target to cache location
Behavior: Fastest option, but files only exist in one location at a time
Important: Automatically enables save-always to prevent cache loss if workflow fails
Copy Strategy
Restore: Files are copied from cache to target location (cache remains intact)
Save: Files are copied from target to cache location (originals remain)
Behavior: Slower than move, but safer as files exist in both locations
Copy-Immutable Strategy
Restore: Files are copied from cache to target location (cache remains intact)
Save: Files are copied from target to cache location only if cache doesn't already exist
Behavior: Prevents accidental cache overwrites, useful for immutable artifacts
Usage
Basic Usage (Combined Action)
yaml
- name: Cache dependencies
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
yaml
- name: Restore dependencies from cache
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
yaml
- name: Save dependencies to cache
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

move (default): Move files between cache and target locations. Note: This automatically enables save-always to prevent cache loss.
copy: Copy files, leaving originals in place
copy-immutable: Copy files, but won't overwrite existing cache files
fail-on-cache-miss
Optional If set to true, the workflow will fail if no valid cache is found. Default: false

save-always
Optional If set to true, the cache will be saved even if the workflow fails. Default: false. Important: When using the move strategy, this is automatically set to true to prevent cache loss. Note: This option is only used with the combined action, not with the separate save action.

Outputs
cache-hit
A boolean value indicating if the cache was found and restored.

restored-key
The key that was used to restore the cache (can be primary key or one of the restore-keys).

Example Workflows
Using the Combined Action
yaml
- name: Cache NPM packages
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
yaml
# Restore cache at the beginning
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
Important Note About Move Strategy
yaml
# ❌ This could lead to cache loss if the job fails
- name: Cache with move strategy (risky)
  uses: bold-dev/action-local-cache@2
  with:
    path: ./important-files
    key: my-cache-key
    strategy: move
    save-always: false  # This is risky with move strategy!

# ✅ Move strategy automatically enables save-always (recommended)
- name: Cache with move strategy (safe)
  uses: bold-dev/action-local-cache@2
  with:
    path: ./important-files
    key: my-cache-key
    strategy: move
    # save-always is automatically true with move strategy
Require Cache Hit (Useful for Deployment Jobs)
yaml
- name: Restore Build Artifacts
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
