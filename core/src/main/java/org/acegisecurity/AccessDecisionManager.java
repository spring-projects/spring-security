/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import org.aopalliance.intercept.MethodInvocation;


/**
 * Makes a final access control (authorization) decision.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AccessDecisionManager {
    //~ Methods ================================================================

    /**
     * Resolves an access control decision for the passed parameters.
     *
     * @param authentication the caller invoking the method
     * @param invocation the method being called
     * @param config the configuration attributes associated with the method
     *        being invoked
     *
     * @throws AccessDeniedException if access is denied
     */
    public void decide(Authentication authentication,
                       MethodInvocation invocation,
                       ConfigAttributeDefinition config)
                throws AccessDeniedException;

    /**
     * Indicates whether this <code>AccessDecisionManager</code> is able to
     * process authorization requests presented with the passed
     * <code>ConfigAttribute</code>.
     * 
     * <p>
     * This allows the <code>SecurityInterceptor</code> to check every
     * configuration attribute can be consumed by the configured
     * <code>AccessDecisionManager</code> and/or <code>RunAsManager</code>.
     * </p>
     *
     * @param attribute a configuration attribute that has been configured
     *        against the <code>SecurityInterceptor</code>
     *
     * @return true if this <code>AccessDecisionManager</code> can support the
     *         passed configuration attribute
     */
    public boolean supports(ConfigAttribute attribute);
}
