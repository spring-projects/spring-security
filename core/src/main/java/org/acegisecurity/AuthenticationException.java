/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Abstract superclass for all exceptions related to the {@link
 * AuthenticationManager} being unable to authenticate an {@link
 * Authentication} object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AuthenticationException extends AcegiSecurityException {
    //~ Constructors ===========================================================

    /**
     * Constructs an <code>AuthenticationException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public AuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    /**
     * Constructs an <code>AuthenticationException</code> with the specified
     * message and no root cause.
     *
     * @param msg the detail message
     */
    public AuthenticationException(String msg) {
        super(msg);
    }
}
