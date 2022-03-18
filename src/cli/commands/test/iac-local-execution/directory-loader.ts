import * as path from 'path';
import { VALID_FILE_TYPES } from './types';
import { isLocalFolder } from '../../../../lib/detect';
import { getFileType } from './file-loader';
import { readdirSync } from 'fs';
import * as fs from 'fs';
import { join } from 'path';

/**
 * Gets all nested directories for the path that we ran a scan.
 * @param pathToScan - the path to scan provided by the user
 * @param maxDepth? - An optional `maxDepth` argument can be provided to limit how deep in the file tree the search will go.
 * @returns {string[]} An array with all the non-empty nested directories in this path
 */
export function getAllDirectoriesForPath(
  pathToScan: string,
  maxDepth?: number,
): string[] {
  // if it is a single file (it has an extension), we return the current path
  if (isSingleFile(pathToScan)) {
    return [path.resolve(pathToScan)];
  }
  return [...getAllDirectoriesForPathGenerator(pathToScan, maxDepth)];
}

/**
 * Gets all the directories included in this path
 * @param pathToScan - the path to scan provided by the user
 * @param maxDepth? - An optional `maxDepth` argument can be provided to limit how deep in the file tree the search will go.
 * @returns {Generator<string>} - a generator which yields the filepaths for the path to scan
 */
function* getAllDirectoriesForPathGenerator(
  pathToScan: string,
  maxDepth?: number,
): Generator<string> {
  for (const filePath of makeFileAndDirectoryGenerator(pathToScan, maxDepth)) {
    if (filePath.directory) yield filePath.directory;
  }
}

/**
 * Gets all file paths for the specific directory
 * @param pathToScan - the path to scan provided by the user
 * @param currentDirectory - the directory which we want to return files for
 * @returns {string[]} An array with all the Terraform filePaths for this directory
 */
export function getFilesForDirectory(
  pathToScan: string,
  currentDirectory: string,
): string[] {
  if (isSingleFile(pathToScan)) {
    if (shouldBeParsed(pathToScan) && !isIgnoredFile(pathToScan)) {
      return [pathToScan];
    }
    return [];
  } else {
    return [...getFilesForDirectoryGenerator(currentDirectory)];
  }
}

/**
 * Iterates through the makeFileAndDirectoryGenerator function and gets all the Terraform files in the specified directory
 * @param pathToScan - the pathToScan to scan provided by the user
 * @returns {Generator<string>} - a generator which holds all the filepaths
 */
export function* getFilesForDirectoryGenerator(
  pathToScan: string,
): Generator<string> {
  for (const filePath of makeFileAndDirectoryGenerator(pathToScan)) {
    if (filePath.file && filePath.file.dir !== pathToScan) {
      // we want to get files that belong just to the current walking directory, not the ones in nested directories
      continue;
    }
    if (
      filePath.file &&
      shouldBeParsed(filePath.file.fileName) &&
      !isIgnoredFile(filePath.file.fileName)
    ) {
      yield filePath.file.fileName;
    }
  }
}

/**
 * makeFileAndDirectoryGenerator is a generator function that helps walking the directory and file structure of this pathToScan
 * @param root
 * @param maxDepth? - An optional `maxDepth` argument can be provided to limit how deep in the file tree the search will go.
 * @returns {Generator<object>} - a generator which yields an object with directories or paths for the path to scan
 */
// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
function* makeFileAndDirectoryGenerator(root = '.', maxDepth?: number) {
  function* generatorHelper(pathToScan, currentDepth) {
    {
      yield { directory: pathToScan };
    }
    if (maxDepth !== currentDepth) {
      for (const dirent of readdirSync(pathToScan, { withFileTypes: true })) {
        if (
          dirent.isDirectory() &&
          fs.readdirSync(join(pathToScan, dirent.name)).length !== 0
        ) {
          yield* generatorHelper(
            join(pathToScan, dirent.name),
            currentDepth + 1,
          );
        } else if (dirent.isFile()) {
          yield {
            file: {
              dir: pathToScan,
              fileName: join(pathToScan, dirent.name),
            },
          };
        }
      }
    }
  }
  yield* generatorHelper(root, 1);
}

const shouldBeParsed = (pathToScan: string): boolean =>
  VALID_FILE_TYPES.includes(getFileType(pathToScan));

const isSingleFile = (pathToScan: string): boolean =>
  !isLocalFolder(pathToScan);

/**
 * Checks if a file should be ignored from loading or not according to the filetype.
 * We ignore the same files that Terraform ignores.
 * https://github.com/hashicorp/terraform/blob/dc63fda44b67300d5161dabcd803426d0d2f468e/internal/configs/parser_config_dir.go#L137-L143
 * @param {string}  pathToScan - The filepath to check
 * @returns {boolean} if the filepath should be ignored or not
 */
export function isIgnoredFile(pathToScan: string): boolean {
  // we normalise the path in case the user tries to scan a single file with a relative path
  // e.g. './my-folder/terraform.tf'
  const normalisedPath = path.normalize(pathToScan);
  return (
    normalisedPath.startsWith('.') || // Unix-like hidden files
    normalisedPath.startsWith('~') || // vim
    (normalisedPath.startsWith('#') && normalisedPath.endsWith('#')) // emacs
  );
}
