/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

import net.sf.acegisecurity.Authentication;


/**
 * Basic concrete implementation of a {@link SecureContext}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecureContextImpl extends ContextImpl implements SecureContext {
    //~ Instance fields ========================================================

    private Authentication authentication;

    //~ Methods ================================================================

    public void setAuthentication(Authentication newAuthentication) {
        this.authentication = newAuthentication;
    }

    public Authentication getAuthentication() {
        return this.authentication;
    }

    public void validate() throws ContextInvalidException {
        super.validate();

        if (authentication == null) {
            throw new ContextInvalidException("Authentication not set");
        }
    }
}
