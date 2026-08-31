import { memo, useMemo } from "react";

import type { CampaignNode, CampaignSearchState, CampaignTransition } from "../types";

interface CampaignSearchTreeProps {
  search: CampaignSearchState;
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}

interface TreeNodeProps {
  node: CampaignNode;
  childrenByParent: Map<string, CampaignNode[]>;
  transitionByChild: Map<string, CampaignTransition>;
  currentNodeId: string | null;
  bestPath: Set<string>;
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}

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
  return value.replace("node-", "").slice(0, 8);
}

const TreeNode = memo(function TreeNode({
  node,
  childrenByParent,
  transitionByChild,
  currentNodeId,
  bestPath,
  selectedNodeId,
  onSelectNode,
}: TreeNodeProps) {
  const children = childrenByParent.get(node.node_id) ?? [];
  const incoming = transitionByChild.get(node.node_id);
  const classes = [
    "campaign-tree-node-card",
    `is-${node.status.toLowerCase().replace("_", "-")}`,
    currentNodeId === node.node_id ? "is-current" : "",
    bestPath.has(node.node_id) ? "is-best-path" : "",
    selectedNodeId === node.node_id ? "is-selected" : "",
  ].filter(Boolean).join(" ");

  return (
    <li className="campaign-tree-node">
      {incoming ? (
        <div className={`campaign-tree-edge is-${incoming.status.toLowerCase()}`}>
          <span>{incoming.trust_boundary_id}</span>
          <code>{incoming.tool}:{incoming.action}</code>
          <b>{incoming.impact_score}</b>
        </div>
      ) : null}
      <button className={classes} type="button" onClick={() => onSelectNode(node.node_id)}>
        <span className="campaign-node-kicker">D{node.depth} · {shortId(node.node_id)}</span>
        <strong>{node.active_environment.toUpperCase()}</strong>
        <small>{node.controlled_environments.map((item) => item.toUpperCase()).join(" · ")}</small>
        <span className="campaign-node-status">{statusLabels[node.status]}</span>
        <b>Impact {node.highest_impact_score}</b>
      </button>
      {children.length > 0 ? (
        <ol className="campaign-tree-children">
          {children.map((child) => (
            <TreeNode
              bestPath={bestPath}
              childrenByParent={childrenByParent}
              currentNodeId={currentNodeId}
              key={child.node_id}
              node={child}
              onSelectNode={onSelectNode}
              selectedNodeId={selectedNodeId}
              transitionByChild={transitionByChild}
            />
          ))}
        </ol>
      ) : null}
    </li>
  );
});

export const CampaignSearchTree = memo(function CampaignSearchTree({
  search,
  selectedNodeId,
  onSelectNode,
}: CampaignSearchTreeProps) {
  const { root, childrenByParent, transitionByChild, bestPath } = useMemo(() => {
    const nodeById = new Map(search.nodes.map((node) => [node.node_id, node]));
    const children = new Map<string, CampaignNode[]>();
    for (const node of search.nodes) {
      if (!node.parent_node_id) continue;
      const siblings = children.get(node.parent_node_id) ?? [];
      siblings.push(node);
      children.set(node.parent_node_id, siblings);
    }
    for (const siblings of children.values()) {
      siblings.sort((left, right) => right.priority_score - left.priority_score);
    }
    const byChild = new Map<string, CampaignTransition>();
    for (const transition of search.transitions) {
      if (transition.to_node_id) byChild.set(transition.to_node_id, transition);
    }
    const path = new Set<string>();
    let cursor = search.best_node_id ? nodeById.get(search.best_node_id) : undefined;
    while (cursor) {
      path.add(cursor.node_id);
      cursor = cursor.parent_node_id ? nodeById.get(cursor.parent_node_id) : undefined;
    }
    return {
      root: search.root_node_id ? nodeById.get(search.root_node_id) : undefined,
      childrenByParent: children,
      transitionByChild: byChild,
      bestPath: path,
    };
  }, [search.best_node_id, search.nodes, search.root_node_id, search.transitions]);

  if (!root) {
    return <p className="monitor-empty">Recon이 끝나면 Campaign 루트 노드가 생성됩니다.</p>;
  }

  return (
    <div className="campaign-tree-viewport">
      <ol className="campaign-tree-root">
        <TreeNode
          bestPath={bestPath}
          childrenByParent={childrenByParent}
          currentNodeId={search.current_node_id}
          node={root}
          onSelectNode={onSelectNode}
          selectedNodeId={selectedNodeId}
          transitionByChild={transitionByChild}
        />
      </ol>
    </div>
  );
});
