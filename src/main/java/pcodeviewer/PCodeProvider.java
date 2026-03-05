package pcodeviewer;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.ItemEvent;

import javax.swing.ButtonGroup;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import resources.Icons;


public class PCodeProvider extends ComponentProviderAdapter {

	private static final String[] SIMPLIFICATION_STYLES =
		{ "decompile", "normalize", "firstpass", "register", "paramid" };

	private JPanel panel;
	private JTextArea textArea;
	private JRadioButton rawButton;
	private JRadioButton highButton;
	private JComboBox<String> styleCombo;
	private JToggleButton prettyButton;
	private JToggleButton ssaButton;
	private JToggleButton seqButton;
	private DockingAction action;
	private Program currentProgram;
	private ProgramLocation currentLocation;
	private PCodeViewerPlugin plugin;

	private DecompInterface decompIfc;
	private Program lastDecompProgram;
	private String lastDecompStyle;

	public PCodeProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = (PCodeViewerPlugin) plugin;
		setTitle("PCode Viewer");
		buildPanel();
		setDefaultWindowPosition(WindowPosition.STACK);
		addToTool();
		createActions();
	}

	private void buildPanel() {
		panel = new JPanel(new BorderLayout());

		JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		rawButton = new JRadioButton("Raw PCode", true);
		highButton = new JRadioButton("High PCode", false);
		ButtonGroup modeGroup = new ButtonGroup();
		modeGroup.add(rawButton);
		modeGroup.add(highButton);

		styleCombo = new JComboBox<>(SIMPLIFICATION_STYLES);
		styleCombo.setEnabled(false);

		rawButton.addActionListener(e -> {
			styleCombo.setEnabled(false);
			ssaButton.setEnabled(false);
			updatePanel();
		});
		highButton.addActionListener(e -> {
			styleCombo.setEnabled(true);
			ssaButton.setEnabled(true);
			updatePanel();
		});
		styleCombo.addActionListener(e -> updatePanel());

		prettyButton = new JToggleButton("Pretty");
		prettyButton.addActionListener(e -> updatePanel());
		styleToggleButton(prettyButton);

		ssaButton = new JToggleButton("Show SSA");
		ssaButton.setEnabled(false);
		ssaButton.addActionListener(e -> updatePanel());
		styleToggleButton(ssaButton);

		seqButton = new JToggleButton("Show Sequence");
		seqButton.addActionListener(e -> updatePanel());
		styleToggleButton(seqButton);

		controlPanel.add(rawButton);
		controlPanel.add(highButton);
		controlPanel.add(new JLabel("Style:"));
		controlPanel.add(styleCombo);
		controlPanel.add(prettyButton);
		controlPanel.add(ssaButton);
		controlPanel.add(seqButton);

		textArea = new JTextArea(40, 80);
		textArea.setEditable(false);
		textArea.append("PCode Viewer: Set the current location inside a function to view its PCode");

		panel.add(controlPanel, BorderLayout.NORTH);
		panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
	}

	private void createActions() {
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	public void locationChanged(Program program, ProgramLocation location) {
		currentProgram = program;
		currentLocation = location;
		if (isVisible()) {
			updatePanel();
		}
	}

	private DecompInterface getDecompInterface() {
		String style = (String) styleCombo.getSelectedItem();
		if (decompIfc == null || currentProgram != lastDecompProgram || !style.equals(lastDecompStyle)) {
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

	private String getPcode(Function f) {
		boolean pretty = prettyButton.isSelected();
		boolean showSsa = ssaButton.isSelected();
		boolean showSeq = seqButton.isSelected();
		if (highButton.isSelected()) {
			return PCodeUtils.highPCodeBlockString(f, getDecompInterface(), pretty, showSsa, showSeq);
		}
		return PCodeUtils.rawPCodeString(currentProgram, f, pretty, showSeq);
	}

	private void updatePanel() {
		if (currentProgram == null || currentLocation == null) {
			return;
		}
		Function func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress());
		if (func != null) {
			textArea.setText(getPcode(func));
			textArea.setCaretPosition(0);
		}
		else {
			textArea.setText("Address " + currentLocation.getAddress().toString() + " is not contained in a function.");
		}
	}

	private static void styleToggleButton(JToggleButton button) {
		Color defaultBg = button.getBackground();
		Color selectedBg = new Color(100, 160, 100);
		button.setOpaque(true);
		button.addItemListener(e -> button.setBackground(
			e.getStateChange() == ItemEvent.SELECTED ? selectedBg : defaultBg));
	}

	public void clear() {
		currentProgram = null;
		currentLocation = null;
		textArea.setText("");
		if (decompIfc != null) {
			decompIfc.dispose();
			decompIfc = null;
			lastDecompProgram = null;
			lastDecompStyle = null;
		}
	}
}
