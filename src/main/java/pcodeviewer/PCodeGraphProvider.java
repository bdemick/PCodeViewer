package pcodeviewer;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.*;

import javax.swing.*;

import docking.WindowPosition;
import ghidra.app.decompiler.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

public class PCodeGraphProvider
		extends VisualGraphComponentProvider<PCodeVertex, PCodeEdge, PCodeGraph> {

	private static final String[] SIMPLIFICATION_STYLES =
		{ "decompile", "normalize", "firstpass", "register", "paramid" };

	private final PCodeViewerPlugin plugin;
	private final VisualGraphView<PCodeVertex, PCodeEdge, PCodeGraph> view;
	private final JPanel mainPanel;

	private JComboBox<String> styleCombo;
	private JToggleButton prettyButton;
	private JToggleButton ssaButton;
	private JToggleButton seqButton;

	private Program currentProgram;
	private ProgramLocation currentLocation;

	private DecompInterface decompIfc;
	private Program lastDecompProgram;
	private String lastDecompStyle;

	public PCodeGraphProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), "PCode Graph", owner);
		this.plugin = (PCodeViewerPlugin) plugin;
		setTitle("PCode Graph");
		setDefaultWindowPosition(WindowPosition.WINDOW);

		view = new VisualGraphView<>();
		view.setLayoutProvider(new PCodeGraphLayoutProvider()); // used by relayout action

		mainPanel = buildPanel();
		addToTool();
	}

	private JPanel buildPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		controlPanel.add(new JLabel("Style:"));
		styleCombo = new JComboBox<>(SIMPLIFICATION_STYLES);
		styleCombo.addActionListener(e -> rebuildGraph());
		controlPanel.add(styleCombo);

		prettyButton = new JToggleButton("Pretty");
		prettyButton.addActionListener(e -> rebuildGraph());
		styleToggleButton(prettyButton);
		controlPanel.add(prettyButton);

		ssaButton = new JToggleButton("Show SSA");
		ssaButton.addActionListener(e -> rebuildGraph());
		styleToggleButton(ssaButton);
		controlPanel.add(ssaButton);

		seqButton = new JToggleButton("Show Sequence");
		seqButton.addActionListener(e -> rebuildGraph());
		styleToggleButton(seqButton);
		controlPanel.add(seqButton);

		panel.add(controlPanel, BorderLayout.NORTH);
		panel.add(view.getViewComponent(), BorderLayout.CENTER);
		return panel;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public VisualGraphView<PCodeVertex, PCodeEdge, PCodeGraph> getView() {
		return view;
	}

	@Override
	public void componentShown() {
		super.componentShown();
		rebuildGraph();
	}

	public void locationChanged(Program program, ProgramLocation location) {
		currentProgram = program;
		currentLocation = location;
		if (isVisible()) {
			rebuildGraph();
		}
	}

	private void rebuildGraph() {
		if (currentProgram == null || currentLocation == null) {
			return;
		}

		Function func =
			currentProgram.getListing().getFunctionContaining(currentLocation.getAddress());
		if (func == null) {
			return;
		}

		DecompileResults results = getDecompInterface().decompileFunction(
			func, DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		if (!results.decompileCompleted()) {
			return;
		}

		HighFunction highFunc = results.getHighFunction();
		if (highFunc == null) {
			return;
		}

		boolean pretty = prettyButton.isSelected();
		boolean showSsa = ssaButton.isSelected();
		boolean showSeq = seqButton.isSelected();
		Language lang = pretty ? highFunc.getLanguage() : null;
		Program p = pretty ? func.getProgram() : null;

		PCodeGraph graph = new PCodeGraph();

		// Build one vertex per basic block
		ArrayList<PcodeBlockBasic> blocks = highFunc.getBasicBlocks();
		Map<Long, PCodeVertex> vertexMap = new LinkedHashMap<>();
		for (PcodeBlockBasic block : blocks) {
			PCodeVertex vertex = new PCodeVertex(block, lang, p, pretty, showSsa, showSeq);
			graph.addVertex(vertex);
			vertexMap.put(block.getStart().getOffset(), vertex);
		}

		// Add control-flow edges
		for (PcodeBlockBasic block : blocks) {
			PCodeVertex from = vertexMap.get(block.getStart().getOffset());
			int outSize = block.getOutSize();
			if (outSize == 1) {
				PCodeVertex to = vertexMap.get(block.getOut(0).getStart().getOffset());
				if (to != null) {
					graph.addEdge(new PCodeEdge(from, to, PCodeEdge.FlowType.UNCONDITIONAL));
				}
			}
			else if (outSize == 2) {
				PCodeVertex trueTarget =
					vertexMap.get(block.getTrueOut().getStart().getOffset());
				PCodeVertex falseTarget =
					vertexMap.get(block.getFalseOut().getStart().getOffset());
				if (trueTarget != null) {
					graph.addEdge(new PCodeEdge(from, trueTarget, PCodeEdge.FlowType.TRUE));
				}
				if (falseTarget != null) {
					graph.addEdge(new PCodeEdge(from, falseTarget, PCodeEdge.FlowType.FALSE));
				}
			}
		}

		PCodeGraphLayout layout = new PCodeGraphLayout(graph);
		graph.setLayout(layout);
		view.setGraph(graph);
		applyEdgeColors();
	}

	@SuppressWarnings("unchecked")
	private void applyEdgeColors() {
		GraphViewer<PCodeVertex, PCodeEdge> viewer = view.getPrimaryGraphViewer();
		if (viewer == null) {
			return;
		}
		Renderer<PCodeVertex, PCodeEdge> renderer = viewer.getRenderer();
		Renderer.Edge<PCodeVertex, PCodeEdge> edgeRenderer = renderer.getEdgeRenderer();
		if (edgeRenderer instanceof VisualEdgeRenderer) {
			VisualEdgeRenderer<PCodeVertex, PCodeEdge> ver =
				(VisualEdgeRenderer<PCodeVertex, PCodeEdge>) edgeRenderer;
			ver.setDrawColorTransformer(PCodeGraphProvider::edgeColor);
		}
	}

	private static Color edgeColor(PCodeEdge e) {
		return switch (e.getFlowType()) {
			case TRUE -> new Color(60, 160, 60);
			case FALSE -> new Color(200, 60, 60);
			case UNCONDITIONAL -> new Color(80, 120, 200);
		};
	}

	private DecompInterface getDecompInterface() {
		String style = (String) styleCombo.getSelectedItem();
		if (decompIfc == null || currentProgram != lastDecompProgram ||
				!style.equals(lastDecompStyle)) {
			if (decompIfc != null) {
				decompIfc.dispose();
			}
			ToolOptions opt = plugin.getTool().getOptions("Decompiler");
			ToolOptions fieldOptions = plugin.getTool().getOptions("Listing Fields");
			DecompileOptions decompOptions = new DecompileOptions();
			decompOptions.grabFromToolAndProgram(fieldOptions, opt, currentProgram);

			decompIfc = new DecompInterface();
			decompIfc.setOptions(decompOptions);
			decompIfc.setSimplificationStyle(style);
			decompIfc.openProgram(currentProgram);
			lastDecompProgram = currentProgram;
			lastDecompStyle = style;
		}
		return decompIfc;
	}

	public void clear() {
		currentProgram = null;
		currentLocation = null;
		if (decompIfc != null) {
			decompIfc.dispose();
			decompIfc = null;
			lastDecompProgram = null;
			lastDecompStyle = null;
		}
	}

	private static void styleToggleButton(JToggleButton button) {
		Color defaultBg = button.getBackground();
		Color selectedBg = new Color(100, 160, 100);
		button.setOpaque(true);
		button.addItemListener(e -> button.setBackground(
			e.getStateChange() == ItemEvent.SELECTED ? selectedBg : defaultBg));
	}

	// -------------------------------------------------------------------------
	// Layout provider
	// -------------------------------------------------------------------------

	private static class PCodeGraphLayoutProvider
			implements LayoutProvider<PCodeVertex, PCodeEdge, PCodeGraph> {

		@Override
		public VisualGraphLayout<PCodeVertex, PCodeEdge> getLayout(PCodeGraph graph,
				TaskMonitor monitor) {
			return new PCodeGraphLayout(graph);
		}

		@Override
		public String getLayoutName() {
			return "PCode Hierarchical";
		}

		@Override
		public Icon getActionIcon() {
			return null;
		}

		@Override
		public int getPriorityLevel() {
			return 100;
		}
	}
}
