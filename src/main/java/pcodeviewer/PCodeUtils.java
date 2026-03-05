package pcodeviewer;

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
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

	public static String rawPCodeString(Program p, Function f, boolean pretty, boolean showSeq) {
		Language lang = pretty ? p.getLanguage() : null;
		StringBuilder sb = new StringBuilder();
		AddressSetView body = f.getBody();
		InstructionIterator instrIter = p.getListing().getInstructions(body, true);
		while (instrIter.hasNext()) {
			Instruction i = instrIter.next();
			for (PcodeOp op : i.getPcode()) {
				String prefix = formatPrefix(i.getAddressString(false, true), op, showSeq);
				String opStr = formatOp(op, lang, p, pretty, false);
				sb.append(prefix).append(":\t").append(opStr).append("\n");
			}
		}
		return sb.toString();
	}

public static String highPCodeBlockString(Function f, DecompInterface decompIfc,
			boolean pretty, boolean showSsa, boolean showSeq) {
		DecompileResults results = decompIfc.decompileFunction(
			f, DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		if (!results.decompileCompleted()) {
			return "Decompilation failed: " + results.getErrorMessage();
		}
		HighFunction highFunc = results.getHighFunction();
		if (highFunc == null) {
			return "No high function available.";
		}
		Language lang = pretty ? highFunc.getLanguage() : null;
		Program p = pretty ? f.getProgram() : null;
		StringBuilder sb = new StringBuilder();
		ArrayList<PcodeBlockBasic> blocks = highFunc.getBasicBlocks();
		for (PcodeBlockBasic block : blocks) {
			sb.append(blockLabel(block)).append("\n");
			Iterator<PcodeOp> ops = block.getIterator();
			while (ops.hasNext()) {
				PcodeOp op = ops.next();
				String baseAddr = op.getSeqnum().getTarget().toString();
				String prefix = formatPrefix(baseAddr, op, showSeq);
				String opStr = formatOp(op, lang, p, pretty, showSsa);
				sb.append(prefix).append(":\t").append(opStr).append("\n");
			}
			int outSize = block.getOutSize();
			if (outSize == 1) {
				sb.append("U: ").append(blockLabel(block.getOut(0))).append("\n");
			}
			else if (outSize == 2) {
				sb.append("T: ").append(blockLabel(block.getTrueOut())).append("\n");
				sb.append("F: ").append(blockLabel(block.getFalseOut())).append("\n");
			}
			sb.append("\n");
		}
		return sb.toString();
	}

	private static String blockLabel(PcodeBlock block) {
		return "block_" + Long.toHexString(block.getStart().getOffset()) + ":";
	}

	private static String formatPrefix(String baseAddr, PcodeOp op, boolean showSeq) {
		if (!showSeq) {
			return baseAddr;
		}
		return String.format("%s: %5s: %2s", baseAddr,
			"0x" + Integer.toHexString(op.getSeqnum().getTime()),
			op.getSeqnum().getOrder());
	}

	private static String formatOp(PcodeOp op, Language lang, Program p,
			boolean pretty, boolean showSsa) {
		if (!pretty && !showSsa) {
			return op.toString();
		}
		Varnode output = op.getOutput();
		String outStr = output != null ? formatVarnode(output, lang, pretty, showSsa) : "---";

		StringBuilder sb = new StringBuilder();
		sb.append(outStr).append(" ").append(op.getMnemonic());

		Varnode[] inputs = op.getInputs();
		for (int i = 0; i < inputs.length; i++) {
			sb.append(" ");
			if (inputs[i] == null) {
				sb.append("---");
			}
			else if (i == 0 && pretty && op.getOpcode() == PcodeOp.CALL && inputs[i].isAddress()) {
				Function callee = p.getFunctionManager().getFunctionAt(inputs[i].getAddress());
				sb.append(callee != null ? callee.getName() : formatVarnode(inputs[i], lang, pretty, showSsa));
			}
			else {
				sb.append(formatVarnode(inputs[i], lang, pretty, showSsa));
			}
		}
		return sb.toString();
	}

	private static String formatVarnode(Varnode v, Language lang, boolean pretty, boolean showSsa) {
		String base = pretty ? v.toString(lang) : v.toString();
		if (showSsa && !v.isConstant() && v instanceof VarnodeAST) {
			base += "_" + ((VarnodeAST) v).getUniqueId();
		}
		return base;
	}
}
