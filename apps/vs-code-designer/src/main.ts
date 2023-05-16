import { LogicAppResolver } from './LogicAppResolver';
import { runPostWorkflowCreateStepsFromCache } from './app/commands/createCodeless/createCodelessSteps/WorkflowCreateStepBase';
import { validateFuncCoreToolsIsLatest } from './app/commands/funcCoreTools/validateFuncCoreToolsIsLatest';
import { registerCommands } from './app/commands/registerCommands';
import { getResourceGroupsApi } from './app/resourcesExtension/getExtensionApi';
import type { AzureAccountTreeItemWithProjects } from './app/tree/AzureAccountTreeItemWithProjects';
import { startDesignTimeApi, stopDesignTimeApi } from './app/utils/codeless/startDesignTimeApi';
import { UriHandler } from './app/utils/codeless/urihandler';
import { registerFuncHostTaskEvents } from './app/utils/funcCoreTools/funcHostTask';
import { isFunctionProject, tryGetFunctionProjectRoot } from './app/utils/verifyIsProject';
import { verifyVSCodeConfigOnActivate } from './app/utils/vsCodeConfig/verifyVSCodeConfigOnActivate';
import { getWorkspaceFolder } from './app/utils/workspace';
import { extensionCommand, logicAppFilter } from './constants';
import { ext } from './extensionVariables';
import { registerAppServiceExtensionVariables } from '@microsoft/vscode-azext-azureappservice';
import {
  callWithTelemetryAndErrorHandling,
  createAzExtOutputChannel,
  registerEvent,
  registerReportIssueCommand,
  registerUIExtensionVariables,
  getAzExtResourceType,
} from '@microsoft/vscode-azext-utils';
import type { IActionContext } from '@microsoft/vscode-azext-utils';
import * as vscode from 'vscode';

const perfStats = {
  loadStartTime: Date.now(),
  loadEndTime: undefined,
};

export async function activate(context: vscode.ExtensionContext) {
  ext.context = context;

  ext.outputChannel = createAzExtOutputChannel('Azure Logic Apps (Standard)', ext.prefix);

  registerUIExtensionVariables(ext);
  registerAppServiceExtensionVariables(ext);

  await callWithTelemetryAndErrorHandling(extensionCommand.activate, async (activateContext: IActionContext) => {
    activateContext.telemetry.properties.isActivationEvent = 'true';
    activateContext.telemetry.measurements.mainFileLoad = (perfStats.loadEndTime - perfStats.loadStartTime) / 1000;

    const test = await isFunctionProject(this.projectPath);
    const workspace = await getWorkspaceFolder(this.projectPath);
    const test2 = await tryGetFunctionProjectRoot(activateContext, workspace);

    console.log('charlie', test, test2);

    startDesignTimeApi(this.projectPath);
    runPostWorkflowCreateStepsFromCache();
    validateFuncCoreToolsIsLatest();

    ext.rgApi = await getResourceGroupsApi();
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    ext.azureAccountTreeItem = ext.rgApi.appResourceTree._rootTreeItem as AzureAccountTreeItemWithProjects;

    callWithTelemetryAndErrorHandling(extensionCommand.validateLogicAppProjects, async (actionContext: IActionContext) => {
      await verifyVSCodeConfigOnActivate(actionContext, vscode.workspace.workspaceFolders);
    });

    registerEvent(
      extensionCommand.validateLogicAppProjects,
      vscode.workspace.onDidChangeWorkspaceFolders,
      async (actionContext: IActionContext, event: vscode.WorkspaceFoldersChangeEvent) => {
        await verifyVSCodeConfigOnActivate(actionContext, event.added);
      }
    );

    context.subscriptions.push(ext.outputChannel);
    context.subscriptions.push(ext.azureAccountTreeItem);

    registerReportIssueCommand(extensionCommand.reportIssue);
    registerCommands();
    registerFuncHostTaskEvents();

    ext.rgApi.registerApplicationResourceResolver(getAzExtResourceType(logicAppFilter), new LogicAppResolver());

    vscode.window.registerUriHandler(new UriHandler());
  });
}

export function deactivate(): Promise<any> {
  stopDesignTimeApi();
  return undefined;
}

perfStats.loadEndTime = Date.now();
