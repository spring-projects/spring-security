/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;


/**
 * Indicates a class can process a specific  {@link
 * net.sf.acegisecurity.Authentication}  implementation.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AuthenticationProvider {
    //~ Methods ================================================================

    /**
     * Performs authentication with the same contract as  {@link
     * net.sf.acegisecurity.AuthenticationManager#authenticate(Authentication)}.
     *
     * @param authentication the authentication request object.
     *
     * @return a fully authenticated object including credentials.
     *
     * @throws AuthenticationException if authentication fails.
     */
    public Authentication authenticate(Authentication authentication)
                                throws AuthenticationException;

    /**
     * Returns true if this <Code>AuthenticationProvider</code> supports the
     * indicated <Code>Authentication</code> object.
     * 
     * <P>
     * Selection of an <code>AuthenticationProvider</code> capable of
     * performing authentication is conducted at runtime the
     * <code>ProviderManager</code>.
     * </p>
     *
     * @return DOCUMENT ME!
     */
    public boolean supports(Class authentication);
}
