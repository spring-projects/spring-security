/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers;

import net.sf.acegisecurity.AuthenticationException;


/**
 * Thrown by {@link ProviderManager} if no  {@link AuthenticationProvider}
 * could be found that supports the presented {@link
 * net.sf.acegisecurity.Authentication} object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ProviderNotFoundException extends AuthenticationException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>ProviderNotFoundException</code> with the specified
     * message.
     *
     * @param msg the detail message
     */
    public ProviderNotFoundException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>ProviderNotFoundException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public ProviderNotFoundException(String msg, Throwable t) {
        super(msg, t);
    }
}
