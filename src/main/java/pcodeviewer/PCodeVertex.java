package pcodeviewer;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

import generic.theme.Gui;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeBlockBasic;

public class PCodeVertex extends AbstractVisualVertex {

	private static final int TEXT_WIDTH = 320;
	private static final Color HEADER_BG = new Color(60, 63, 85);
	private static final Color HEADER_FG = Color.WHITE;

	private final long blockStart;
	private final JPanel component;

	public PCodeVertex(PcodeBlockBasic block, Language lang, Program p,
			boolean pretty, boolean showSsa, boolean showSeq) {
		this.blockStart = block.getStart().getOffset();

		JTextPane textPane = new JTextPane();
		textPane.setEditable(false);
		Gui.registerFont(textPane, "font.listing.base");

		StyledWriter writer = new StyledWriter(textPane.getStyledDocument());
		PCodeUtils.writeBlockPCode(block, lang, p, pretty, showSsa, showSeq, writer);

		// Fix width, measure height
		textPane.setSize(new Dimension(TEXT_WIDTH, Short.MAX_VALUE));
		Dimension textPref = textPane.getPreferredSize();
		textPane.setPreferredSize(new Dimension(TEXT_WIDTH, textPref.height));

		JLabel header = new JLabel("block_" + Long.toHexString(blockStart) + ":");
		header.setForeground(HEADER_FG);
		header.setBackground(HEADER_BG);
		header.setOpaque(true);
		header.setBorder(new EmptyBorder(2, 6, 2, 6));

		component = new JPanel(new BorderLayout());
		component.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		component.add(header, BorderLayout.NORTH);
		component.add(textPane, BorderLayout.CENTER);

		int totalH = textPref.height + header.getPreferredSize().height + 2;
		component.setPreferredSize(new Dimension(TEXT_WIDTH + 2, totalH));
	}

	public long getBlockStart() {
		return blockStart;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void dispose() {
		// nothing to dispose
	}
}
