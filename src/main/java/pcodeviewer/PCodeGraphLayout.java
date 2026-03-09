package pcodeviewer;

import java.util.*;

import edu.uci.ics.jung.graph.Graph;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;

public class PCodeGraphLayout extends AbstractVisualGraphLayout<PCodeVertex, PCodeEdge> {

	public PCodeGraphLayout(Graph<PCodeVertex, PCodeEdge> graph) {
		super(graph, "PCode Hierarchical");
		initialize();
	}

	@Override
	protected GridLocationMap<PCodeVertex, PCodeEdge> performInitialGridLayout(
			VisualGraph<PCodeVertex, PCodeEdge> g) throws CancelledException {

		Collection<PCodeVertex> vertices = g.getVertices();

		// Entry = lowest block start address (function entry point)
		PCodeVertex entry = vertices.stream()
				.min(Comparator.comparingLong(PCodeVertex::getBlockStart))
				.get();

		GridLocationMap<PCodeVertex, PCodeEdge> gridMap =
			new GridLocationMap<>(entry, 0, 0);

		// BFS from entry to assign rows (depth level)
		Map<PCodeVertex, Integer> rowMap = new LinkedHashMap<>();
		Queue<PCodeVertex> queue = new LinkedList<>();
		rowMap.put(entry, 0);
		queue.add(entry);

		while (!queue.isEmpty()) {
			PCodeVertex current = queue.poll();
			int nextRow = rowMap.get(current) + 1;
			for (PCodeEdge edge : g.getOutEdges(current)) {
				PCodeVertex successor = edge.getEnd();
				if (!rowMap.containsKey(successor)) {
					rowMap.put(successor, nextRow);
					queue.add(successor);
				}
			}
		}

		// Assign any unreachable vertices below the rest
		int maxRow = rowMap.values().stream().mapToInt(Integer::intValue).max().orElse(0);
		for (PCodeVertex v : vertices) {
			if (!rowMap.containsKey(v)) {
				rowMap.put(v, ++maxRow);
			}
		}

		// Group by row, assign columns left-to-right
		Map<Integer, List<PCodeVertex>> byRow = new TreeMap<>();
		for (Map.Entry<PCodeVertex, Integer> e : rowMap.entrySet()) {
			byRow.computeIfAbsent(e.getValue(), k -> new ArrayList<>()).add(e.getKey());
		}

		int row = 0;
		for (List<PCodeVertex> rowVertices : byRow.values()) {
			for (int col = 0; col < rowVertices.size(); col++) {
				gridMap.set(rowVertices.get(col), row, col);
			}
			row++;
		}

		return gridMap;
	}

	@Override
	public VisualGraph<PCodeVertex, PCodeEdge> getVisualGraph() {
		@SuppressWarnings("unchecked")
		VisualGraph<PCodeVertex, PCodeEdge> vg =
			(VisualGraph<PCodeVertex, PCodeEdge>) getGraph();
		return vg;
	}

	@Override
	public AbstractVisualGraphLayout<PCodeVertex, PCodeEdge> createClonedLayout(
			VisualGraph<PCodeVertex, PCodeEdge> newGraph) {
		@SuppressWarnings("unchecked")
		Graph<PCodeVertex, PCodeEdge> jungGraph =
			(Graph<PCodeVertex, PCodeEdge>) newGraph;
		return new PCodeGraphLayout(jungGraph);
	}
}
