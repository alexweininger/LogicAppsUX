/* eslint-disable @typescript-eslint/ban-types */
import type { RootState } from '../../state/store';
import { useIsDarkMode, useIsMonitoringView, useIsReadOnly, useShowChatBot } from '../../state/workflowLoadingSelectors';
import { DesignerCommandBar } from './DesignerCommandBar';
import type { ConnectionAndAppSetting, ConnectionsData, ParametersData } from './Models/Workflow';
import type { WorkflowApp } from './Models/WorkflowApp';
import { ApiManagementService } from './Services/ApiManagement';
import { ArtifactService } from './Services/Artifact';
import { ChildWorkflowService } from './Services/ChildWorkflow';
import { parseApimOperationIds, serializeApimOperations } from './Services/ConsumptionSerializationHelpers';
import { FileSystemConnectionCreationClient } from './Services/FileSystemConnectionCreationClient';
import { HttpClient } from './Services/HttpClient';
import {
  listCallbackUrl,
  saveWorkflowConsumption,
  useCurrentTenantId,
  useWorkflowAndArtifactsConsumption,
  useWorkflowApp,
} from './Services/WorkflowAndArtifacts';
import { ArmParser } from './Utilities/ArmParser';
import { WorkflowUtility } from './Utilities/Workflow';
import { Chatbot } from '@microsoft/chatbot';
import {
  ApiManagementInstanceService,
  BaseAppServiceService,
  BaseFunctionService,
  BaseGatewayService,
  BaseOAuthService,
  ConsumptionConnectionService,
  ConsumptionConnectorService,
  ConsumptionOperationManifestService,
  ConsumptionSearchService,
} from '@microsoft/designer-client-services-logic-apps';
import type { Workflow } from '@microsoft/logic-apps-designer';
import { DesignerProvider, BJSWorkflowProvider, Designer } from '@microsoft/logic-apps-designer';
import { guid, isArmResourceId } from '@microsoft/utils-logic-apps';
import * as React from 'react';
import { useSelector } from 'react-redux';

const apiVersion = '2020-06-01';
const httpClient = new HttpClient();

const DesignerEditorConsumption = () => {
  const { id: workflowId } = useSelector((state: RootState) => ({
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    id: state.workflowLoader.resourcePath!,
  }));

  const isDarkMode = useIsDarkMode();
  const readOnly = useIsReadOnly();
  const isMonitoringView = useIsMonitoringView();
  const showChatBot = useShowChatBot();

  // const workflowName = workflowId.split('/').splice(-1)[0];
  const siteResourceId = new ArmParser(workflowId).topmostResourceId;
  const {
    data: workflowAndArtifactsData,
    isLoading: isWorkflowAndArtifactsLoading,
    isError: isWorklowAndArtifactsError,
    error: workflowAndArtifactsError,
  } = useWorkflowAndArtifactsConsumption(workflowId);
  const {
    data: workflowAppData,
    isLoading: isWorkflowAppLoading,
    isError: isWorkflowAppError,
    error: workflowAppError,
  } = useWorkflowApp(siteResourceId, true);
  const { data: tenantId } = useCurrentTenantId();
  const [designerID, setDesignerID] = React.useState(guid());

  const { workflow, connectionsData, connectionReferences, parameters } = React.useMemo(
    () => getDataForConsumption(workflowAndArtifactsData),
    [workflowAndArtifactsData]
  );
  const { definition } = workflow;

  // TODO: Rework this for Consumption
  const addConnectionData = async (_connectionAndSetting: ConnectionAndAppSetting): Promise<void> => {
    // addConnectionInJson(connectionAndSetting, connectionsData ?? {});
    // addOrUpdateAppSettings(connectionAndSetting.settings, settingsData?.properties ?? {});
  };

  const getConnectionConfiguration = async (connectionId: string): Promise<any> => {
    if (!connectionId) {
      return Promise.resolve();
    }

    const connectionName = connectionId.split('/').splice(-1)[0];
    const connectionInfo =
      connectionsData?.serviceProviderConnections?.[connectionName] ?? connectionsData?.apiManagementConnections?.[connectionName];

    if (connectionInfo) {
      // TODO(psamband): Add new settings in this blade so that we do not resolve all the appsettings in the connectionInfo.
      const resolvedConnectionInfo = WorkflowUtility.resolveConnectionsReferences(JSON.stringify(connectionInfo), {});
      delete resolvedConnectionInfo.displayName;

      return {
        connection: resolvedConnectionInfo,
      };
    }

    return undefined;
  };

  const discardAllChanges = () => {
    setDesignerID(guid());
  };
  const canonicalLocation = WorkflowUtility.convertToCanonicalFormat(workflowAppData?.location ?? '');
  const services = React.useMemo(
    () =>
      getDesignerServices(
        workflowId,
        connectionsData ?? {},
        workflowAppData as WorkflowApp,
        addConnectionData,
        getConnectionConfiguration,
        tenantId,
        canonicalLocation
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [workflowId, connectionsData, workflowAppData, addConnectionData, tenantId, canonicalLocation, designerID]
  );

  const [parsedDefinition, setParsedDefinition] = React.useState<any>(undefined);

  React.useEffect(() => {
    (async () => {
      if (!services) return;
      if (!(definition as any)?.actions) return;
      await parseApimOperationIds(definition, services.apimService);
      setParsedDefinition(definition);
    })();
  }, [definition, services]);

  // Our iframe root element is given a strange padding (not in this repo), this removes it
  React.useEffect(() => {
    const root = document.getElementById('root');
    if (root) {
      root.style.padding = '0px';
      root.style.overflow = 'hidden';
    }
  }, []);

  const isLoading = React.useMemo(
    () => isWorkflowAndArtifactsLoading || isWorkflowAppLoading,
    [isWorkflowAndArtifactsLoading, isWorkflowAppLoading]
  );

  const isError = React.useMemo(() => isWorklowAndArtifactsError || isWorkflowAppError, [isWorklowAndArtifactsError, isWorkflowAppError]);

  const error = React.useMemo(() => workflowAndArtifactsError ?? workflowAppError, [workflowAndArtifactsError, workflowAppError]);

  if (!parsedDefinition || isLoading) {
    // eslint-disable-next-line react/jsx-no-useless-fragment
    return <></>;
  }

  if (isError) {
    throw error;
  }

  if (isWorklowAndArtifactsError) throw workflowAndArtifactsError;

  const saveWorkflowFromDesigner = async (workflowFromDesigner: Workflow): Promise<void> => {
    if (!workflowAndArtifactsData) return;
    const { definition, connectionReferences, parameters } = workflowFromDesigner;
    const workflowToSave = {
      ...workflow,
      definition,
      parameters,
      connections: {},
    };

    try {
      const newConnectionsObj: Record<string, any> = {};
      if (Object.keys(connectionReferences ?? {}).length) {
        await Promise.all(
          Object.keys(connectionReferences).map(async (referenceKey) => {
            const reference = connectionReferences[referenceKey];
            if (isArmResourceId(reference?.connection?.id) && !connectionsData?.managedApiConnections?.[referenceKey]) {
              const {
                api: { id: apiId },
                connection: { id: connectionId },
                connectionName,
                connectionProperties,
              } = reference;
              newConnectionsObj[referenceKey] = {
                id: apiId,
                connectionId,
                connectionName,
                connectionProperties,
              };
            }
          })
        );
      }
      workflowToSave.connections = newConnectionsObj;

      await serializeApimOperations(workflowToSave.definition, services.apimService);
      const response = await saveWorkflowConsumption(workflowAndArtifactsData, workflowToSave);
      alert(`Workflow saved successfully!`);
      return response;
    } catch (e: any) {
      console.error(e);
      alert(`Error saving workflow, check console for error object`);
      return;
    }
  };

  return (
    <div key={designerID} style={{ height: 'inherit', width: 'inherit' }}>
      <DesignerProvider locale={'en-US'} options={{ services, isDarkMode, readOnly, isMonitoringView, isConsumption: true }}>
        {workflow?.definition ? (
          <BJSWorkflowProvider workflow={{ definition: parsedDefinition, connectionReferences, parameters }}>
            <div style={{ height: 'inherit', width: 'inherit' }}>
              <DesignerCommandBar
                id={workflowId}
                saveWorkflow={saveWorkflowFromDesigner}
                discard={discardAllChanges}
                location={canonicalLocation}
                isReadOnly={readOnly}
                isDarkMode={isDarkMode}
                isConsumption
              />
              <Designer />
              {showChatBot ? <Chatbot /> : null}
            </div>
          </BJSWorkflowProvider>
        ) : null}
      </DesignerProvider>
    </div>
  );
};

const getDesignerServices = (
  workflowId: string,
  connectionsData: ConnectionsData,
  workflowApp: WorkflowApp,
  addConnection: (data: ConnectionAndAppSetting) => Promise<void>,
  getConfiguration: (connectionId: string) => Promise<any>,
  tenantId: string | undefined,
  location: string
): any => {
  const siteResourceId = new ArmParser(workflowId).topmostResourceId;
  const armUrl = 'https://management.azure.com';
  const baseUrl = `${armUrl}${siteResourceId}/hostruntime/runtime/webhooks/workflow/api/management`;
  const workflowName = workflowId.split('/').splice(-1)[0];
  const workflowIdWithHostRuntime = `${siteResourceId}/hostruntime/runtime/webhooks/workflow/api/management/workflows/${workflowName}`;
  const { subscriptionId, resourceGroup } = new ArmParser(workflowId);

  const defaultServiceParams = { baseUrl, httpClient, apiVersion };

  const connectionService = new ConsumptionConnectionService({
    baseUrl,
    apiVersion,
    httpClient,
    apiHubServiceDetails: {
      apiVersion: '2018-07-01-preview',
      baseUrl: armUrl,
      subscriptionId,
      resourceGroup,
      location,
    },
    tenantId,
    workflowAppDetails: { appName: siteResourceId.split('/').splice(-1)[0], identity: workflowApp?.identity as any },
    readConnections: () => Promise.resolve(connectionsData),
    writeConnection: addConnection as any,
    connectionCreationClients: {
      FileSystem: new FileSystemConnectionCreationClient({
        baseUrl: armUrl,
        subscriptionId,
        resourceGroup,
        appName: siteResourceId.split('/').splice(-1)[0],
        apiVersion: '2022-03-01',
        httpClient,
      }),
    },
  });
  const apimService = new ApiManagementInstanceService({
    apiVersion: '2019-12-01',
    baseUrl,
    subscriptionId,
    httpClient,
  });
  const childWorkflowService = new ChildWorkflowService({ apiVersion, baseUrl: armUrl, siteResourceId, httpClient, workflowName });
  const artifactService = new ArtifactService({
    apiVersion,
    baseUrl: armUrl,
    siteResourceId,
    httpClient,
    integrationAccountCallbackUrl: undefined,
  });
  const apiManagementService = new ApiManagementService({ service: apimService });
  const appService = new BaseAppServiceService({ baseUrl: armUrl, apiVersion, subscriptionId, httpClient });
  const connectorService = new ConsumptionConnectorService({
    ...defaultServiceParams,
    clientSupportedOperations: [
      ['connectionProviders/localWorkflowOperation', 'invokeWorkflow'],
      ['connectionProviders/xmlOperations', 'xmlValidation'],
      ['connectionProviders/xmlOperations', 'xmlTransform'],
      ['connectionProviders/liquidOperations', 'liquidJsonToJson'],
      ['connectionProviders/liquidOperations', 'liquidJsonToText'],
      ['connectionProviders/liquidOperations', 'liquidXmlToJson'],
      ['connectionProviders/liquidOperations', 'liquidXmlToText'],
      ['connectionProviders/flatFileOperations', 'flatFileDecoding'],
      ['connectionProviders/flatFileOperations', 'flatFileEncoding'],
      ['connectionProviders/swiftOperations', 'SwiftDecode'],
      ['connectionProviders/swiftOperations', 'SwiftEncode'],
      ['/connectionProviders/apiManagementOperation', 'apiManagement'],
      ['connectionProviders/http', 'httpswaggeraction'],
      ['connectionProviders/http', 'httpswaggertrigger'],
    ].map(([connectorId, operationId]) => ({ connectorId, operationId })),
    getConfiguration,
    schemaClient: {
      getWorkflowSwagger: (args: any) => childWorkflowService.getWorkflowTriggerSchema(args.parameters.name),
      getApimOperationSchema: (args: any) => {
        const { configuration, parameters, isInput } = args;
        if (!configuration?.connection?.apiId) {
          throw new Error('Missing api information to make dynamic call');
        }
        return apiManagementService.getOperationSchema(configuration.connection.apiId, parameters.operationId, isInput);
      },
      getSwaggerOperationSchema: (args: any) => {
        const { parameters, nodeMetadata, isInput } = args;
        const swaggerUrl = nodeMetadata?.['apiDefinitionUrl'];
        if (!swaggerUrl) return Promise.resolve();
        return appService.getOperationSchema(swaggerUrl, parameters.operationId, isInput);
      },
    },
    valuesClient: {
      getWorkflows: () => childWorkflowService.getWorkflowsWithRequestTrigger(),
      getMapArtifacts: (args: any) => {
        const { mapType, mapSource } = args.parameters;
        return artifactService.getMapArtifacts(mapType, mapSource);
      },
      getSwaggerOperations: (args: any) => {
        const { nodeMetadata } = args;
        const swaggerUrl = nodeMetadata?.['apiDefinitionUrl'];
        return appService.getOperations(swaggerUrl);
      },
      getSchemaArtifacts: (args: any) => artifactService.getSchemaArtifacts(args.parameters.schemaSource),
      getApimOperations: (args: any) => {
        const { configuration } = args;
        if (!configuration?.connection?.apiId) {
          throw new Error('Missing api information to make dynamic call');
        }

        return apiManagementService.getOperations(configuration?.connection?.apiId);
      },
    },
    apiHubServiceDetails: {
      apiVersion: '2018-07-01-preview',
      baseUrl: armUrl,
      subscriptionId,
      resourceGroup,
    },
    workflowReferenceId: '',
  });
  const gatewayService = new BaseGatewayService({
    baseUrl: armUrl,
    httpClient,
    apiVersions: {
      subscription: apiVersion,
      gateway: '2016-06-01',
    },
  });

  const operationManifestService = new ConsumptionOperationManifestService(defaultServiceParams);
  const searchService = new ConsumptionSearchService({
    ...defaultServiceParams,
    apiHubServiceDetails: { apiVersion: '2018-07-01-preview', subscriptionId, location },
    isDev: false,
  });

  const oAuthService = new BaseOAuthService({
    ...defaultServiceParams,
    apiVersion: '2018-07-01-preview',
    subscriptionId,
    resourceGroup,
    location,
  });

  const workflowService = {
    getCallbackUrl: (triggerName: string) => listCallbackUrl(workflowIdWithHostRuntime, triggerName, true),
    getAppIdentity: () => workflowApp.identity,
    isExplicitAuthRequiredForManagedIdentity: () => true,
  };

  const functionService = new BaseFunctionService({
    baseUrl: armUrl,
    apiVersion,
    subscriptionId,
    httpClient,
  });

  // const loggerService = new Stan({
  //   resourceID: workflowId,
  //   designerVersion: packagejson.dependencies['@microsoft/logic-apps-designer'],
  //   designerID,
  // });

  return {
    appService,
    connectionService,
    connectorService,
    gatewayService,
    operationManifestService,
    searchService,
    loggerService: null,
    oAuthService,
    workflowService,
    apimService,
    functionService,
  };
};

const getDataForConsumption = (data: any) => {
  const properties = data?.properties as any;

  const definition = removeProperties(properties?.definition, ['parameters']);
  const connections = properties?.parameters?.$connections?.value ?? {};

  const workflow = { definition, connections };
  const connectionsData: Record<string, any> = {};
  const connectionReferences = formatConnectionReferencesForConsumption(connections);
  const parameters: ParametersData = formatWorkflowParametersForConsumption(properties);

  return { workflow, connectionsData, connectionReferences, parameters };
};

const removeProperties = (obj: any = {}, props: string[] = []): Object => {
  return Object.fromEntries(Object.entries(obj).filter(([key]) => !props.includes(key)));
};

const formatConnectionReferencesForConsumption = (connectionReferences: Record<string, any>): any => {
  return Object.fromEntries(
    Object.entries(connectionReferences).map(([key, value]) => [key, formatConnectionReferenceForConsumption(value)])
  );
};

const formatConnectionReferenceForConsumption = (connectionReference: any): any => {
  const connectionReferenceCopy = { ...connectionReference };
  connectionReferenceCopy.connection = { id: connectionReference.connectionId };
  delete connectionReferenceCopy.connectionId;
  connectionReferenceCopy.api = { id: connectionReference.id };
  delete connectionReferenceCopy.id;
  return connectionReferenceCopy;
};

const formatWorkflowParametersForConsumption = (properties: any): ParametersData => {
  const parameters = removeProperties(properties?.definition?.parameters, ['$connections']) as ParametersData;
  Object.entries(properties?.parameters ?? {}).forEach(([key, parameter]: [key: string, parameter: any]) => {
    if (parameters[key]) parameters[key].value = parameter?.value;
  });
  return parameters;
};

export default DesignerEditorConsumption;