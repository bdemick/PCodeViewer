package pcodeviewer;

import ghidra.graph.viewer.edge.AbstractVisualEdge;

public class PCodeEdge extends AbstractVisualEdge<PCodeVertex> {

	public enum FlowType {
		UNCONDITIONAL, TRUE, FALSE
	}

	private final FlowType flowType;

	public PCodeEdge(PCodeVertex start, PCodeVertex end, FlowType flowType) {
		super(start, end);
		this.flowType = flowType;
	}

	public FlowType getFlowType() {
		return flowType;
	}

	@Override
	public PCodeEdge cloneEdge(PCodeVertex start, PCodeVertex end) {
		return new PCodeEdge(start, end, flowType);
	}
}
