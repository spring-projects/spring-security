/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Thrown if an authentication request is rejected because there is no {@link
 * Authentication} object in the  {@link
 * net.sf.acegisecurity.context.SecureContext}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationCredentialsNotFoundException
    extends AuthenticationException {
    //~ Constructors ===========================================================

    /**
     * Constructs an <code>AuthenticationCredentialsNotFoundException</code>
     * with the specified message.
     *
     * @param msg the detail message
     */
    public AuthenticationCredentialsNotFoundException(String msg) {
        super(msg);
    }

    /**
     * Constructs an <code>AuthenticationCredentialsNotFoundException</code>
     * with the specified message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public AuthenticationCredentialsNotFoundException(String msg, Throwable t) {
        super(msg, t);
    }
}
