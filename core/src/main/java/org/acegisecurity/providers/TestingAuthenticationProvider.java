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
 * An {@link AuthenticationProvider} implementation for the  {@link
 * TestingAuthenticationToken}.
 * 
 * <p>
 * It simply accepts as valid whatever is contained within the
 * <code>TestingAuthenticationToken</code>.
 * </p>
 * 
 * <p>
 * The purpose of this implementation is to facilitate unit testing. This
 * provider should <B>never be enabled on a production system</b>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TestingAuthenticationProvider implements AuthenticationProvider {
    //~ Methods ================================================================

    public Authentication authenticate(Authentication authentication)
                                throws AuthenticationException {
        return authentication;
    }

    public boolean supports(Class authentication) {
        if (TestingAuthenticationToken.class.isAssignableFrom(authentication)) {
            return true;
        } else {
            return false;
        }
    }
}
