import { readFile } from 'node:fs/promises';
import { createModelGateway, createGenerationService, BrokerClient } from '../../../packages/core/src/index.ts';
import type { Config } from './config.ts';
import type { EngineDependencies } from './engine.ts';
import type { Store } from './store.ts';
import { recordModelCalls } from './model-records.ts';
import { validatedTelemetry } from './telemetry.ts';
import { AccessBrokerClient } from '../../../packages/core/src/access.ts';
import { AppAccountBrokerClient } from '../../../packages/core/src/app-accounts.ts';
import { ConnectorBrokerClient } from '../../../packages/core/src/connectors.ts';
import { AdapterBrokerClient } from '../../../packages/core/src/connector-adapters.ts';
import { ConnectionRevocationClient } from '../../../packages/core/src/connection-revocation.ts';
import { DirectoryBrokerClient } from '../../../packages/core/src/directory.ts';
import { generationConnectionInventory } from './connection-context.ts';
import { createIntegrationResearch } from './integration-research.ts';
import { knownProtectedValues } from './protected-values.ts';
import { frozenPreviousSourceSelection, ModelCheckpointError } from './model-checkpoints.ts';
export async function configureDependencies(config: Config, store: Store): Promise<EngineDependencies> {
  const dependencies: EngineDependencies = {}, protectedValues = knownProtectedValues(config);
  dependencies.generationConnections = appId => generationConnectionInventory(store, appId, { secretKey: config.secretKey, ownerSubject: config.ownerSubject, connectorStatus: dependencies.connectorStatus, filesystemStatus: dependencies.filesystemStatus });
  dependencies.researchIntegrations = createIntegrationResearch(store, { catalogFile: process.env.INTEGRATION_CATALOG_FILE ?? 'models/integrations.json', knownSecrets: protectedValues });
  if (config.openaiApiKey || config.anthropicApiKey) {
    const gateway = recordModelCalls(await createModelGateway(protectedValues), store, config.secretKey); dependencies.planAndGenerate = createGenerationService({ gateway, templateRoot: process.env.TEMPLATE_ROOT ?? 'templates', freezePreviousSourceSelection: (input, selection, budget) => {
      if (!budget.worker) throw new ModelCheckpointError('The current worker lease is required before source selection.');
      return frozenPreviousSourceSelection(store, config.secretKey, input, budget.worker.owner, selection);
    } });
  }
  if (config.brokerUrl && config.brokerToken) {
    const approvalKey = process.env.BROKER_APPROVAL_KEY_FILE ? (await readFile(process.env.BROKER_APPROVAL_KEY_FILE, 'utf8')).trim() : process.env.BROKER_APPROVAL_KEY;
    if (!approvalKey) throw new Error('BROKER_APPROVAL_KEY_FILE is required when the broker is configured.');
    const broker = new BrokerClient({ url: config.brokerUrl, token: config.brokerToken, approvalKey });
    const identity = new AccessBrokerClient({ url: config.brokerUrl, token: config.brokerToken, approvalKey });
    const accounts = new AppAccountBrokerClient({ url: config.brokerUrl, token: config.brokerToken, approvalKey });
    dependencies.appAccountSnapshot = input => accounts.snapshot(input); dependencies.disableAppAccount = input => accounts.disable(input); dependencies.appAccountOperation = input => accounts.operation(input);
    const connectors = new ConnectorBrokerClient({ url: config.brokerUrl, token: config.brokerToken, approvalKey });
    const adapters = new AdapterBrokerClient({ url: config.brokerUrl, token: config.brokerToken, approvalKey });
    const revocations = new ConnectionRevocationClient({ url: config.brokerUrl, token: config.brokerToken, approvalKey });
    dependencies.connectionRevocationSnapshot = input => revocations.snapshot(input); dependencies.revokeConnection = input => revocations.revoke(input); dependencies.connectionRevocationStatus = input => revocations.status(input);
    const directory = new DirectoryBrokerClient({ url: config.brokerUrl, token: config.brokerToken, approvalKey });
    dependencies.directoryIdentityKeys = input => directory.keys(input); dependencies.directoryIdentitySubject = input => directory.subject(input); dependencies.directoryIdentityConfiguration = input => directory.configuration(input);
    dependencies.filesystemSources = appId => adapters.filesystemSources(appId); dependencies.provisionFilesystem = input => adapters.provisionFilesystem(input); dependencies.filesystemStatus = input => adapters.filesystemStatus(input);
    dependencies.provisionSamba = input => connectors.provision(input); dependencies.connectorStatus = input => connectors.status(input);
    dependencies.accessSnapshot = input => identity.snapshot(input); dependencies.applyAccessPolicy = input => identity.applyPolicy(input); dependencies.acceptAppInvitation = input => identity.acceptInvitation(input); dependencies.accessOperation = input => identity.operation(input);
    dependencies.verify = input => broker.verify(input); dependencies.deploy = input => broker.deploy(input); dependencies.telemetry = async () => {
      return validatedTelemetry(await broker.telemetry());
    };
    dependencies.operation = input => broker.operation(input);
    dependencies.cancelOperation = input => broker.cancelOperation(input);
    dependencies.previousSource = input => broker.source(input);
    dependencies.observe = input => broker.observe(input);
    dependencies.recoverRelease = input => broker.recover(input);
    dependencies.publicCatalog = () => broker.publicCatalog();
    dependencies.publishedCatalog = () => broker.publishedCatalog();
  }
  return dependencies;
}
