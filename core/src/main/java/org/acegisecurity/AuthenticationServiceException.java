/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Thrown if an authentication request could not be processed due to a system
 * problem.
 * 
 * <p>
 * This might be thrown if a backend authentication repository is  unavailable.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationServiceException extends AuthenticationException {
    //~ Constructors ===========================================================

    /**
     * Constructs an <code>AuthenticationServiceException</code> with the
     * specified message.
     *
     * @param msg the detail message
     */
    public AuthenticationServiceException(String msg) {
        super(msg);
    }

    /**
     * Constructs an <code>AuthenticationServiceException</code> with the
     * specified message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public AuthenticationServiceException(String msg, Throwable t) {
        super(msg, t);
    }
}
