import { MethodArgs } from '../args';
import { processCommandArgs } from './process-command-args';
import * as legacyError from '../../lib/errors/legacy-errors';
import * as fs from 'fs';
import * as snykPolicyLib from 'snyk-policy';
import { getIacOrgSettings } from './test/iac-local-execution/org-settings/get-iac-org-settings';
import { UnsupportedEntitlementCommandError } from './test/iac-local-execution/assert-iac-options-flag';
import config from '../../lib/config';
import {
  parseDriftAnalysisResults,
  updateExcludeInPolicy,
} from '../../lib/iac/drift';

export default async (...args: MethodArgs): Promise<any> => {
  const { options } = processCommandArgs(...args);

  // Ensure that this update-exclude-policy command can only be runned when using `snyk iac update-exclude-policy`
  // Avoid `snyk update-exclude-policy` direct usage
  if (options.iac != true) {
    return legacyError('update-exclude-policy');
  }

  // Ensure that we are allowed to run that command
  // by checking the entitlement
  const orgPublicId = options.org ?? config.org;
  const iacOrgSettings = await getIacOrgSettings(orgPublicId);
  if (!iacOrgSettings.entitlements?.iacDrift) {
    throw new UnsupportedEntitlementCommandError(
      'update-exclude-policy',
      'iacDrift',
    );
  }

  try {
    const analysis = parseDriftAnalysisResults(fs.readFileSync(0).toString());
    const policy = await snykPolicyLib.load();
    await updateExcludeInPolicy(policy, analysis, options);
    await snykPolicyLib.save(policy);
  } catch (e) {
    const err = new Error('Error running `iac update-exclude-policy` ' + e);
    return Promise.reject(err);
  }
};
