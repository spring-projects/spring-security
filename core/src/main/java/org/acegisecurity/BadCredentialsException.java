/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Thrown if an authentication request is rejected because the credentials are
 * invalid. For this exception to be thrown, it means the account is neither
 * locked nor disabled.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BadCredentialsException extends AuthenticationException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>BadCredentialsException</code> with the specified
     * message.
     *
     * @param msg the detail message
     */
    public BadCredentialsException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>BadCredentialsException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public BadCredentialsException(String msg, Throwable t) {
        super(msg, t);
    }
}
