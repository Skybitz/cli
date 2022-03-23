import { startMockServer } from './helpers';
import envPaths from 'env-paths';
import { driftctlVersion } from '../../../../src/lib/iac/drift';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { getFixturePath } from '../../util/getFixturePath';
import * as uuid from 'uuid';
import * as rimraf from 'rimraf';
import { FakeServer } from '../../../acceptance/fake-server';

const paths = envPaths('snyk');

jest.setTimeout(50_000);

describe('iac report', () => {
  let server: FakeServer;
  let run: (
    cmd: string,
  ) => Promise<{ stdout: string; stderr: string; exitCode: number }>;
  let teardown: () => void;
  let API_HOST: string;

  beforeAll(async () => {
    ({ server, run, teardown } = await startMockServer());
    API_HOST = `http://localhost:${server.getPort()}`;
  });

  afterEach(() => {
      server.restore();
  });

  afterAll(async () => teardown());

  it('should return exit code 1', async () => {
    // Act
    const { exitCode } = await run(
      `snyk iac report ./iac/arm/rule_test.json`,
    );
    
    // Assert
    expect(exitCode).toEqual(1)
    
  })

  it('should include test results in the output', async () => {
    const { stdout } = await run(
      `snyk iac report ./iac/arm/rule_test.json`,
    );

    expect(stdout).toContain(
      'Infrastructure as code issues:',
    );
  });

  it('should include a link to the projects page in the output', async () => {
    const { stdout } = await run(
      `snyk iac report ./iac/arm/rule_test.json`,
    );

    expect(stdout).toContain(
      `Your test results are available at: ${API_HOST}/org/test-org/projects under the name arm`,
    );
  });

  it('should forward the scan results to the /iac-cli-share-results endpoint', async () => {
    // Act
    await run(
      `snyk iac report ./iac/arm/rule_test.json`,
    );

    // Assert
    const testRequests = server
      .getRequests()
      .filter((request) => request.url?.includes('/iac-cli-share-results'));

    expect(testRequests.length).toEqual(1);
    expect(testRequests[0]).toMatchObject({
      body: [
        {
          identity: {
            type: 'armconfig',
            targetFile: './iac/arm/rule_test.json',
          },
          facts: [],
          findings: expect.arrayContaining([]),
          name: 'arm',
          target: {
            name: 'arm',
          },
        },
      ],
    });
  });

  describe("without the 'iacCliShareResults' feature flag", () => {
   
    it('should return an error status code', async () => {
      // Arrange
      server.setFeatureFlag('iacCliShareResults', false);

      // Act
      const { exitCode } = await run(
        `snyk iac report ./iac/arm/rule_test.json`,
      );

      // Assert
      expect(exitCode).toBe(2);
    });

    it('should print an appropriate error message', async () => {
      // Arrange
      server.setFeatureFlag('iacCliShareResults', false);

      // Act
      const { stdout } = await run(
        `snyk iac report ./iac/arm/rule_test.json`,
      );

      // Assert
      expect(stdout).toMatch(
        'Flag "--report" is only supported if feature flag "iacCliShareResults" is enabled. To enable it, please contact Snyk support.',
      );
    });
  })

  describe("when used without a preceding 'iac'", () => {
    it('should return an error status code', async () => {
      // Act
      const { exitCode } = await run(
        `snyk report ./iac/arm/rule_test.json`,
      );

      // Assert
      expect(exitCode).toBe(2);
    });

    it('should print an appropriate error message', async () => {
      // Act
      const { stdout } = await run(
        `snyk report ./iac/arm/rule_test.json`,
      );

      // Assert
      expect(stdout).toContain(
        'Not a recognised option',
      );
    });
  })
});
