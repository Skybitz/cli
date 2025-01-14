import { loadContentForFiles, NoFilesToScanError } from './file-loader';
import * as path from 'path';
import { parseTerraformFiles } from './file-parser';
import { IacFileParsed, IacFileParseFailure } from './types';
import {
  isIgnoredFile,
  isSingleFile,
  shouldBeParsed,
  makeFileAndDirectoryGenerator,
} from './handle-terraform-files-utils';

/**
 * This function handles everything from filtering out Terraform files  directory by directory,
 * loading them, sending them to the parser and getting the parsing results back.
 * Then it concatenates and returns the new parsing results with the existing parsing results.
 * @param pathToScan - the path to scan provided by the user
 * @param maxDepth? - an optional maxDepth of directories if provided by the detection-depth flag
 * @returns { parsedFiles, failedFiles} - all the parsing results so far
 */
export async function loadAndParseTerraformFiles(
  pathToScan: string,
  maxDepth?: number,
): Promise<{
  parsedFiles: Array<IacFileParsed>;
  failedFiles: Array<IacFileParseFailure>;
}> {
  let parsedFiles: IacFileParsed[] = [],
    failedFiles: IacFileParseFailure[] = [];
  const allDirectories = getAllDirectoriesForPath(pathToScan, maxDepth);

  // we load and parse files directory by directory
  // this is because we need all files in the same directory to share the same variable context
  for (const currentDirectory of allDirectories) {
    const filePathsInDirectory = getFilesForDirectory(
      pathToScan,
      currentDirectory,
    );
    const tfFilesToParse = await loadContentForFiles(filePathsInDirectory);
    const {
      parsedFiles: parsedTfFiles,
      failedFiles: failedTfFiles,
    } = parseTerraformFiles(tfFilesToParse);
    parsedFiles = parsedFiles.concat(parsedTfFiles);
    failedFiles = failedFiles.concat(failedTfFiles);
  }

  if (parsedFiles.length === 0) {
    throw new NoFilesToScanError();
  }

  return { parsedFiles, failedFiles };
}

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
 * Gets all file paths for the specific directory. If the provided path is a supported file, then it gets returned.
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
    return [...getTerraformFilesInDirectoryGenerator(currentDirectory)];
  }
}

/**
 * Iterates through the makeFileAndDirectoryGenerator function and gets all the Terraform files in the specified directory
 * @param pathToScan - the pathToScan to scan provided by the user
 * @returns {Generator<string>} - a generator which holds all the filepaths
 */
export function* getTerraformFilesInDirectoryGenerator(
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
