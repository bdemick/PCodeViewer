package pcodeviewer;

import java.awt.Color;

import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

class StyledWriter {
	private final StyledDocument doc;

	StyledWriter(StyledDocument doc) {
		this.doc = doc;
	}

	void clear() {
		try {
			doc.remove(0, doc.getLength());
		}
		catch (BadLocationException e) {
			// document bounds are guaranteed valid
		}
	}

	void append(String text, Color color) {
		if (color == null) {
			append(text);
			return;
		}
		SimpleAttributeSet attrs = new SimpleAttributeSet();
		StyleConstants.setForeground(attrs, color);
		try {
			doc.insertString(doc.getLength(), text, attrs);
		}
		catch (BadLocationException e) {
			// document bounds are guaranteed valid
		}
	}

	void append(String text) {
		try {
			doc.insertString(doc.getLength(), text, null);
		}
		catch (BadLocationException e) {
			// document bounds are guaranteed valid
		}
	}
}
