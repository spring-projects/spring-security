/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

/**
 * Exotic implementation of a {@link Context}.
 * 
 * <p>
 * Requires the context to be set with a <code>magicNumber</code> of 7. Tests
 * validation in the unit tests.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ExoticContext implements Context {
    //~ Instance fields ========================================================

    private int magicNumber;

    //~ Methods ================================================================

    public void setMagicNumber(int magicNumber) {
        this.magicNumber = magicNumber;
    }

    public int getMagicNumber() {
        return magicNumber;
    }

    public void validate() throws ContextInvalidException {
        if (magicNumber != 7) {
            throw new ContextInvalidException("Magic number is not 7");
        }
    }
}
