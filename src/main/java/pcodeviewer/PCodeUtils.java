package pcodeviewer;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public final class PCodeUtils {
	private PCodeUtils() {
		throw new UnsupportedOperationException();
	}
	
	public static String rawPCodeString(Program p, Function f) {
		// Dump the function's raw PCode as a string prefixed by the address.
		String pcodeStr = new String();
		AddressSetView body = f.getBody();
		InstructionIterator instrIter = p.getListing().getInstructions(body, true);
		while (instrIter.hasNext()) {
			Instruction i = instrIter.next();
			for (PcodeOp pcode : i.getPcode()) {
				pcodeStr += (i.getAddressString(false, true) + ":\t" + pcode.toString() + "\n");
			}
		}
		
		return pcodeStr;
	}

}
