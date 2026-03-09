package pcodeviewer;

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.viewer.field.ListingColors;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.util.task.TaskMonitor;

public final class PCodeUtils {
	private PCodeUtils() {
		throw new UnsupportedOperationException();
	}

	public static void writeRawPCode(Program p, Function f, boolean pretty, boolean showSeq,
			StyledWriter writer) {
		Language lang = pretty ? p.getLanguage() : null;
		AddressSetView body = f.getBody();
		InstructionIterator instrIter = p.getListing().getInstructions(body, true);
		while (instrIter.hasNext()) {
			Instruction i = instrIter.next();
			for (PcodeOp op : i.getPcode()) {
				writePrefix(i.getAddressString(false, true), op, showSeq, writer);
				writer.append(":\t");
				writeOp(op, lang, p, pretty, false, writer);
				writer.append("\n");
			}
		}
	}

	public static void writeHighPCodeBlocks(Function f, DecompInterface decompIfc,
			boolean pretty, boolean showSsa, boolean showSeq, StyledWriter writer) {
		DecompileResults results = decompIfc.decompileFunction(
			f, DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		if (!results.decompileCompleted()) {
			writer.append("Decompilation failed: " + results.getErrorMessage());
			return;
		}
		HighFunction highFunc = results.getHighFunction();
		if (highFunc == null) {
			writer.append("No high function available.");
			return;
		}
		Language lang = pretty ? highFunc.getLanguage() : null;
		Program p = pretty ? f.getProgram() : null;
		ArrayList<PcodeBlockBasic> blocks = highFunc.getBasicBlocks();
		for (PcodeBlockBasic block : blocks) {
			writeBlockLabel(block, writer);
			writer.append("\n");
			writeBlockPCode(block, lang, p, pretty, showSsa, showSeq, writer);
			int outSize = block.getOutSize();
			if (outSize == 1) {
				writer.append("U: ", ListingColors.MnemonicColors.NORMAL);
				writeBlockLabel(block.getOut(0), writer);
				writer.append("\n");
			}
			else if (outSize == 2) {
				writer.append("T: ", ListingColors.MnemonicColors.NORMAL);
				writeBlockLabel(block.getTrueOut(), writer);
				writer.append("\n");
				writer.append("F: ", ListingColors.MnemonicColors.NORMAL);
				writeBlockLabel(block.getFalseOut(), writer);
				writer.append("\n");
			}
			writer.append("\n");
		}
	}

	public static void writeBlockPCode(PcodeBlockBasic block, Language lang, Program p,
			boolean pretty, boolean showSsa, boolean showSeq, StyledWriter writer) {
		Iterator<PcodeOp> ops = block.getIterator();
		while (ops.hasNext()) {
			PcodeOp op = ops.next();
			writePrefix(op.getSeqnum().getTarget().toString(), op, showSeq, writer);
			writer.append(":\t");
			writeOp(op, lang, p, pretty, showSsa, writer);
			writer.append("\n");
		}
	}

	private static void writeBlockLabel(PcodeBlock block, StyledWriter writer) {
		writer.append("block_" + Long.toHexString(block.getStart().getOffset()) + ":",
			ListingColors.PcodeColors.LABEL);
	}

	private static void writePrefix(String baseAddr, PcodeOp op, boolean showSeq,
			StyledWriter writer) {
		writer.append(baseAddr, ListingColors.ADDRESS);
		if (showSeq) {
			writer.append(String.format(": %5s: %2s",
				"0x" + Integer.toHexString(op.getSeqnum().getTime()),
				op.getSeqnum().getOrder()));
		}
	}

	private static void writeOp(PcodeOp op, Language lang, Program p,
			boolean pretty, boolean showSsa, StyledWriter writer) {
		Varnode output = op.getOutput();
		if (output != null) {
			writeVarnode(output, lang, pretty, showSsa, writer);
		}
		else {
			writer.append("---");
		}
		writer.append(" ");
		writer.append(op.getMnemonic(), ListingColors.MnemonicColors.NORMAL);

		Varnode[] inputs = op.getInputs();
		for (int i = 0; i < inputs.length; i++) {
			writer.append(" ");
			if (inputs[i] == null) {
				writer.append("---");
			}
			else if (i == 0 && pretty && op.getOpcode() == PcodeOp.CALL &&
					inputs[i].isAddress()) {
				Function callee = p.getFunctionManager().getFunctionAt(inputs[i].getAddress());
				if (callee != null) {
					writer.append(callee.getName(), ListingColors.FunctionColors.NAME);
				}
				else {
					writeVarnode(inputs[i], lang, pretty, showSsa, writer);
				}
			}
			else {
				writeVarnode(inputs[i], lang, pretty, showSsa, writer);
			}
		}
	}

	private static void writeVarnode(Varnode v, Language lang, boolean pretty, boolean showSsa,
			StyledWriter writer) {
		String text = pretty ? v.toString(lang) : v.toString();
		if (v.isRegister()) {
			writer.append(text, ListingColors.REGISTER);
		}
		else if (v.isConstant()) {
			writer.append(text, ListingColors.CONSTANT);
		}
		else if (v.isAddress()) {
			writer.append(text, ListingColors.ADDRESS);
		}
		else {
			writer.append(text, ListingColors.PcodeColors.VARNODE);
		}
		if (showSsa && !v.isConstant() && v instanceof VarnodeAST) {
			writer.append("_" + ((VarnodeAST) v).getUniqueId());
		}
	}
}
