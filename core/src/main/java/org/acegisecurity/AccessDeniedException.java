/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Thrown if an {@link Authentication} object does not hold a required
 * authority.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AccessDeniedException extends AcegiSecurityException {
    //~ Constructors ===========================================================

    /**
     * Constructs an <code>AccessDeniedException</code> with the specified
     * message.
     *
     * @param msg the detail message
     */
    public AccessDeniedException(String msg) {
        super(msg);
    }

    /**
     * Constructs an <code>AccessDeniedException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public AccessDeniedException(String msg, Throwable t) {
        super(msg, t);
    }
}
