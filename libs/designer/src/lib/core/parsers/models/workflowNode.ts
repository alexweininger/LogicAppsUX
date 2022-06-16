import { equals, isObject } from '@microsoft-logic-apps/utils';

export interface WorkflowGraph {
  id: string;
  children: WorkflowNode[];
  edges: WorkflowEdge[];
}

export interface WorkflowNode {
  id: string;
  children?: WorkflowGraph[];
  height: number;
  width: number;
  type: 'testNode' | 'scopeHeader' | 'subgraphHeader' | 'hiddenNode';
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
  type?: 'buttonEdge' | 'onlyEdge' | 'hiddenEdge';
}

export const isWorkflowNode = (node: any): node is WorkflowNode => {
  return isObject(node) && typeof node.id === 'string' && typeof node.height === 'number' && typeof node.width === 'number';
};

export const isWorkflowGraph = (node: any): node is WorkflowGraph => {
  return isObject(node) && typeof node.id === 'string' && typeof node.children === 'object' && typeof node.edges === 'object';
};

export const isRootNode = (graph: WorkflowGraph, nodeId: string): boolean => {
  return !graph.edges.some((edge) => equals(edge.target, nodeId));
};
