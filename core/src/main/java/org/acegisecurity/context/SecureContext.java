/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

import net.sf.acegisecurity.Authentication;


/**
 * A {@link Context} that also stores {@link Authentication} information.
 * 
 * <p>
 * This interface must be implemented on contexts that will be presented to the
 * Acegi Security System for Spring, as it is required by the  {@link
 * net.sf.acegisecurity.SecurityInterceptor}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface SecureContext {
    //~ Methods ================================================================

    public void setAuthentication(Authentication newAuthentication);

    public Authentication getAuthentication();
}
