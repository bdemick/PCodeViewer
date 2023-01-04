package pcodeviewer;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import resources.Icons;


public class PCodeProvider extends ComponentProviderAdapter {

	private JPanel panel;
	private JTextArea textArea;
	private DockingAction action;
	private Program currentProgram;
	private ProgramLocation currentLocation;
	private PCodeViewerPlugin plugin;

	public PCodeProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = (PCodeViewerPlugin) plugin;
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		textArea = new JTextArea(40, 80);
		textArea.setEditable(false);
		textArea.append(plugin.getName() + ": Set the current location inside a function to view its PCode");
		panel.add(new JScrollPane(textArea));
		setVisible(true);
	}

	// TODO: Customize actions
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
	
	private String getPcode(Function f) {
		String pcodeString = PCodeUtils.rawPCodeString(currentProgram, f);
		return pcodeString;
	}
	
	private void updatePanel() {
		// Update the panel information, but only if the function scope has changed.
		Function func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress());
		if (func != null) {
			textArea.setText(getPcode(func));
		}
		else {
			textArea.setText("Address " + currentLocation.getAddress().toString() + " is not contained in a function.");
		}
	}

	public void clear() {
		// Clear stuff as needed
		currentProgram = null;
		currentLocation = null;
		textArea.setText("");
	}
}