import { memo, useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { CampaignNode, CampaignSearchState, CampaignTransition } from "../types";

interface CampaignSearchTreeProps {
  search: CampaignSearchState;
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}

interface CampaignGraphNodeData extends Record<string, unknown> {
  node: CampaignNode;
  incoming: CampaignTransition | null;
  current: boolean;
  bestPath: boolean;
  selected: boolean;
  onSelect: (nodeId: string) => void;
}

type CampaignFlowNode = Node<CampaignGraphNodeData, "campaignNode">;

const NODE_WIDTH = 148;
const ROW_GAP = 78;

const statusLabels: Record<CampaignNode["status"], string> = {
  QUEUED: "Frontier",
  EXPLORING: "탐색 중",
  IMPACT_VERIFIED: "영향 검증",
  BLOCKED: "차단",
  PRUNED: "가지치기",
  BACKTRACKING: "복귀 중",
  ROLLED_BACK: "복귀 완료",
  ERROR: "오류",
};

function shortId(value: string): string {
  return value.replace("node-", "").slice(0, 6);
}

function compactBoundary(value: string): string {
  return value.replace("TB-", "");
}

function CampaignGraphNode({ data }: NodeProps<CampaignFlowNode>) {
  const { node, incoming } = data;
  const classes = [
    "campaign-graph-node-card",
    `is-${node.status.toLowerCase().replaceAll("_", "-")}`,
    data.current ? "is-current" : "",
    data.bestPath ? "is-best-path" : "",
    data.selected ? "is-selected" : "",
  ].filter(Boolean).join(" ");

  return (
    <div className="campaign-graph-node" style={{ width: NODE_WIDTH }}>
      <Handle className="campaign-node-handle" position={Position.Left} type="target" />
      <button
        aria-label={`깊이 ${node.depth}, ${node.active_environment.toUpperCase()}, ${statusLabels[node.status]}, 영향 ${node.highest_impact_score}`}
        className={`${classes} nodrag nopan`}
        onClick={() => data.onSelect(node.node_id)}
        title={incoming ? `${incoming.trust_boundary_id} · ${incoming.tool}:${incoming.action}` : "Campaign root"}
        type="button"
      >
        <span className="campaign-graph-node-kicker">
          <b>D{node.depth}</b>
          <code>{shortId(node.node_id)}</code>
          <i aria-hidden="true" />
        </span>
        <span className="campaign-graph-node-main">
          <strong>{node.active_environment.toUpperCase()}</strong>
          <b>{node.highest_impact_score}</b>
        </span>
        <span className="campaign-graph-node-meta">
          <small>{statusLabels[node.status]}</small>
          <code>{node.controlled_environments.length} env</code>
        </span>
      </button>
      <Handle className="campaign-node-handle" position={Position.Right} type="source" />
    </div>
  );
}

const nodeTypes: NodeTypes = { campaignNode: memo(CampaignGraphNode) };

function edgeColor(transition: CampaignTransition, bestPath: boolean): string {
  if (bestPath) return "#ff8b87";
  if (transition.status === "FAILED" || transition.status === "BLOCKED") return "#f06d68";
  if (transition.rollback_status === "VERIFIED") return "#75d2a6";
  return "#686a75";
}

export const CampaignSearchTree = memo(function CampaignSearchTree({
  search,
  selectedNodeId,
  onSelectNode,
}: CampaignSearchTreeProps) {
  const graph = useMemo(() => {
    const nodeById = new Map(search.nodes.map((node) => [node.node_id, node]));
    const maxDepth = search.nodes.reduce((depth, node) => Math.max(depth, node.depth), 0);
    const levelGap = maxDepth <= 2 ? 300 : maxDepth <= 4 ? 240 : 196;
    const childrenByParent = new Map<string, CampaignNode[]>();
    const transitionByChild = new Map<string, CampaignTransition>();

    for (const node of search.nodes) {
      if (!node.parent_node_id) continue;
      const siblings = childrenByParent.get(node.parent_node_id) ?? [];
      siblings.push(node);
      childrenByParent.set(node.parent_node_id, siblings);
    }
    for (const siblings of childrenByParent.values()) {
      siblings.sort((left, right) => right.priority_score - left.priority_score);
    }
    for (const transition of search.transitions) {
      if (transition.to_node_id) transitionByChild.set(transition.to_node_id, transition);
    }

    const bestPath = new Set<string>();
    let cursor = search.best_node_id ? nodeById.get(search.best_node_id) : undefined;
    while (cursor) {
      bestPath.add(cursor.node_id);
      cursor = cursor.parent_node_id ? nodeById.get(cursor.parent_node_id) : undefined;
    }

    const positions = new Map<string, { x: number; y: number }>();
    let nextLeafRow = 0;
    const placeNode = (node: CampaignNode): number => {
      const children = childrenByParent.get(node.node_id) ?? [];
      let y: number;
      if (children.length === 0) {
        y = nextLeafRow * ROW_GAP;
        nextLeafRow += 1;
      } else {
        const childRows = children.map(placeNode);
        y = (childRows[0] + childRows[childRows.length - 1]) / 2;
      }
      positions.set(node.node_id, { x: node.depth * levelGap, y });
      return y;
    };

    const root = search.root_node_id ? nodeById.get(search.root_node_id) : undefined;
    if (root) placeNode(root);

    const nodes: CampaignFlowNode[] = search.nodes.map((node) => ({
      id: node.node_id,
      type: "campaignNode",
      position: positions.get(node.node_id) ?? {
        x: node.depth * levelGap,
        y: nextLeafRow++ * ROW_GAP,
      },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      selectable: true,
      draggable: false,
      data: {
        node,
        incoming: transitionByChild.get(node.node_id) ?? null,
        current: search.current_node_id === node.node_id,
        bestPath: bestPath.has(node.node_id),
        selected: selectedNodeId === node.node_id,
        onSelect: onSelectNode,
      },
    }));

    const edges: Edge[] = search.transitions.flatMap((transition) => {
      if (!transition.to_node_id || !nodeById.has(transition.to_node_id)) return [];
      const isBestPath = bestPath.has(transition.from_node_id)
        && bestPath.has(transition.to_node_id);
      const color = edgeColor(transition, isBestPath);
      return [{
        id: transition.transition_id,
        source: transition.from_node_id,
        target: transition.to_node_id,
        type: "smoothstep",
        animated: transition.status === "RUNNING" || transition.status === "BACKTRACKING",
        label: `${compactBoundary(transition.trust_boundary_id)} · ${transition.impact_score}`,
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 12, height: 12 },
        style: { stroke: color, strokeWidth: isBestPath ? 2.2 : 1.25 },
        labelStyle: { fill: isBestPath ? "#ffd0ce" : "#c2c3ca", fontSize: 8, fontWeight: 700 },
        labelBgStyle: { fill: "#282930", fillOpacity: 0.94 },
        labelBgPadding: [4, 2] as [number, number],
        labelBgBorderRadius: 3,
      }];
    });

    return { nodes, edges, hasRoot: Boolean(root) };
  }, [onSelectNode, search.best_node_id, search.current_node_id, search.nodes, search.root_node_id, search.transitions, selectedNodeId]);

  if (!graph.hasRoot) {
    return <p className="monitor-empty">Recon이 끝나면 Campaign 루트 노드가 생성됩니다.</p>;
  }

  return (
    <div className="campaign-tree-viewport">
      <ReactFlow
        className="campaign-flow"
        defaultEdgeOptions={{ type: "smoothstep" }}
        edges={graph.edges}
        fitView
        fitViewOptions={{ padding: 0.12, minZoom: 0.42, maxZoom: 1 }}
        maxZoom={1.6}
        minZoom={0.18}
        nodeTypes={nodeTypes}
        nodes={graph.nodes}
        nodesConnectable={false}
        nodesDraggable={false}
        onNodeClick={(_, node) => onSelectNode(node.id)}
        panOnScroll
        proOptions={{ hideAttribution: true }}
        zoomOnDoubleClick={false}
      >
        <Background color="#42434c" gap={22} size={1} variant={BackgroundVariant.Dots} />
        <Controls position="top-right" showInteractive={false} />
      </ReactFlow>
    </div>
  );
});
