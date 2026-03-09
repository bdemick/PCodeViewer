package pcodeviewer;

import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;

public class PCodeGraph extends DefaultVisualGraph<PCodeVertex, PCodeEdge> {

	private VisualGraphLayout<PCodeVertex, PCodeEdge> layout;

	public void setLayout(VisualGraphLayout<PCodeVertex, PCodeEdge> layout) {
		this.layout = layout;
	}

	@Override
	public VisualGraphLayout<PCodeVertex, PCodeEdge> getLayout() {
		return layout;
	}

	@Override
	public PCodeGraph copy() {
		PCodeGraph newGraph = new PCodeGraph();
		for (PCodeVertex v : getVertices()) {
			newGraph.addVertex(v);
		}
		for (PCodeEdge e : getEdges()) {
			newGraph.addEdge(e);
		}
		return newGraph;
	}
}
