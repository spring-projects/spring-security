/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import net.sf.acegisecurity.context.ContextInvalidException;
import net.sf.acegisecurity.context.SecureContextImpl;


/**
 * Demonstrates subclassing the {@link SecureContextImpl} with
 * application-specific requirements.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ExoticSecureContext extends SecureContextImpl {
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
        super.validate();

        if (magicNumber != 7) {
            throw new ContextInvalidException("Magic number is not 7");
        }
    }
}
