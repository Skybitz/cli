import { ArgsOptions, MethodArgs } from '../args';
import { IaCTestFlags } from './test/iac-local-execution/types';
import { TestCommandResult } from './types';
import test from './test';
import { hasFeatureFlag } from '../../lib/feature-flags';
import { Options } from '../../lib/types';
import { UnsupportedFeatureFlagError } from '../../lib/errors';

export default async function report(
  ...args: MethodArgs
): Promise<TestCommandResult> {
  const options = extractOptionsFromArgs(args);

  await assertReportSupported(options);

  options.report = true;
  return await test(...args, options as ArgsOptions);
}

function extractOptionsFromArgs(args: MethodArgs): IaCTestFlags {
  return typeof args[args.length - 1] === 'object'
    ? (args.pop() as IaCTestFlags)
    : {};
}

async function assertReportSupported(options: IaCTestFlags) {
  const isReportSupported = await hasFeatureFlag(
    'cliShareResults',
    options as Options,
  );
  if (!isReportSupported) {
    throw new UnsupportedFeatureFlagError('cliShareResults');
  }
}
