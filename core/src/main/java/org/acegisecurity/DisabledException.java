/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Thrown if an authentication request is rejected because the account is
 * disabled. Makes no assertion as to whether or not the credentials were
 * valid.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DisabledException extends AuthenticationException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>DisabledException</code> with the specified message.
     *
     * @param msg the detail message
     */
    public DisabledException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>DisabledException</code> with the specified message
     * and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public DisabledException(String msg, Throwable t) {
        super(msg, t);
    }
}
