/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import org.springframework.core.NestedRuntimeException;


/**
 * Abstract superclass for all exceptions thrown in the security package and
 * subpackages.
 * 
 * <p>
 * Note that this is a runtime (unchecked) exception. Security exceptions are
 * usually fatal; there is no reason for them to be checked.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AcegiSecurityException extends NestedRuntimeException {
    //~ Constructors ===========================================================

    /**
     * Constructs an <code>AcegiSecurityException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public AcegiSecurityException(String msg, Throwable t) {
        super(msg, t);
    }

    /**
     * Constructs an <code>AcegiSecurityException</code> with the specified
     * message and no root cause.
     *
     * @param msg the detail message
     */
    public AcegiSecurityException(String msg) {
        super(msg);
    }
}
