/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao;

import net.sf.acegisecurity.AuthenticationException;


/**
 * Thrown if an {@link AuthenticationDao} implementation cannot locate a {@link
 * User} by its username.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UsernameNotFoundException extends AuthenticationException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>UsernameNotFoundException</code> with the specified
     * message.
     *
     * @param msg the detail message.
     */
    public UsernameNotFoundException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>UsernameNotFoundException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message.
     * @param t root cause
     */
    public UsernameNotFoundException(String msg, Throwable t) {
        super(msg, t);
    }
}
