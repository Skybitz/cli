import { isLocalFolder } from '../../../../lib/detect';
import {
  EngineType,
  IacFileParsed,
  IacFileParseFailure,
  IaCTestFlags,
  RulesOrigin,
  SafeAnalyticsOutput,
  TestReturnValue,
} from './types';
import { addIacAnalytics } from './analytics';
import { TestLimitReachedError } from './usage-tracking';
import { filterIgnoredIssues } from './policy';
import { TestResult } from '../../../../lib/snyk-test/legacy';
import {
  applyCustomSeverities,
  cleanLocalCache,
  formatScanResults,
  getIacOrgSettings,
  parseFiles,
  scanFiles,
  trackUsage,
} from './measurable-methods';
import { UnsupportedEntitlementError } from '../../../../lib/errors/unsupported-entitlement-error';
import config from '../../../../lib/config';
import { findAndLoadPolicy } from '../../../../lib/policy';
import { isFeatureFlagSupportedForOrg } from '../../../../lib/feature-flags';
import { initRules } from './rules';
import { loadContentForFiles, NoFilesToScanError } from './file-loader';
import { formatAndShareResults } from './share-results';
import {
  getAllDirectoriesForPath,
  getFilesForDirectory,
} from './directory-loader';

// this method executes the local processing engine and then formats the results to adapt with the CLI output.
// this flow is the default GA flow for IAC scanning.
export async function test(
  pathToScan: string,
  options: IaCTestFlags,
): Promise<TestReturnValue> {
  try {
    const orgPublicId = options.org ?? config.org;
    const iacOrgSettings = await getIacOrgSettings(orgPublicId);

    if (!iacOrgSettings.entitlements?.infrastructureAsCode) {
      throw new UnsupportedEntitlementError('infrastructureAsCode');
    }

    const rulesOrigin = await initRules(iacOrgSettings, options);

    const policy = await findAndLoadPolicy(pathToScan, 'iac', options);

    const isTFVarSupportEnabled = (
      await isFeatureFlagSupportedForOrg(
        'iacTerraformVarSupport',
        iacOrgSettings.meta.org,
      )
    ).ok;

    let allParsedFiles: IacFileParsed[] = [],
      allFailedFiles: IacFileParseFailure[] = [];
    const allDirectories = getAllDirectoriesForPath(
      pathToScan,
      options.detectionDepth,
    );

    // we load and parse files directory by directory
    // this is because we need all files in the same directory to share the same variable context for Terraform
    for (const currentDirectory of allDirectories) {
      const filePathsInDirectory = getFilesForDirectory(
        pathToScan,
        currentDirectory,
      );
      const filesToParse = await loadContentForFiles(filePathsInDirectory);
      const { parsedFiles, failedFiles } = await parseFiles(
        filesToParse,
        options,
        isTFVarSupportEnabled,
      );
      allParsedFiles = allParsedFiles.concat(parsedFiles);
      allFailedFiles = allFailedFiles.concat(failedFiles);
    }

    if (allParsedFiles.length === 0) {
      throw new NoFilesToScanError();
    }

    // Duplicate all the files and run them through the custom engine.
    if (rulesOrigin !== RulesOrigin.Internal) {
      allParsedFiles.push(
        ...allParsedFiles.map((file) => ({
          ...file,
          engineType: EngineType.Custom,
        })),
      );
    }

    const scannedFiles = await scanFiles(allParsedFiles);
    const resultsWithCustomSeverities = await applyCustomSeverities(
      scannedFiles,
      iacOrgSettings.customPolicies,
    );

    let projectPublicIds: Record<string, string> = {};
    if (options.report) {
      projectPublicIds = await formatAndShareResults(
        resultsWithCustomSeverities,
        options,
        orgPublicId,
        policy,
      );
    }

    const formattedResults = formatScanResults(
      resultsWithCustomSeverities,
      options,
      iacOrgSettings.meta,
      projectPublicIds,
    );

    const { filteredIssues, ignoreCount } = filterIgnoredIssues(
      policy,
      formattedResults,
    );

    try {
      await trackUsage(filteredIssues);
    } catch (e) {
      if (e instanceof TestLimitReachedError) {
        throw e;
      }
      // If something has gone wrong, err on the side of allowing the user to
      // run their tests by squashing the error.
    }

    addIacAnalytics(filteredIssues, {
      ignoredIssuesCount: ignoreCount,
      rulesOrigin,
    });

    // TODO: add support for proper typing of old TestResult interface.
    return {
      results: (filteredIssues as unknown) as TestResult[],
      // NOTE: No file or parsed file data should leave this function.
      failures: isLocalFolder(pathToScan)
        ? allFailedFiles.map(removeFileContent)
        : undefined,
    };
  } finally {
    cleanLocalCache();
  }
}

export function removeFileContent({
  filePath,
  fileType,
  failureReason,
  projectType,
}: IacFileParsed | IacFileParseFailure): SafeAnalyticsOutput {
  return {
    filePath,
    fileType,
    failureReason,
    projectType,
  };
}
