/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import org.aopalliance.intercept.MethodInvocation;


/**
 * Creates a new temporary {@link Authentication} object for the current method
 * invocation only.
 * 
 * <P>
 * This interface permits implementations to replace the
 * <code>Authentication</code> object that applies to the current method
 * invocation only. The {@link SecurityInterceptor} will replace the
 * <code>Authentication</code> object held in the  {@link
 * net.sf.acegisecurity.context.SecureContext} for the duration of the method
 * invocation only, returning it to the original  <code>Authentication</code>
 * object when the method invocation completes.
 * </p>
 * 
 * <P>
 * This is provided so that systems with two layers of objects can be
 * established. One layer is public facing and has normal secure methods with
 * the granted authorities expected to be held by external callers. The other
 * layer is private, and is only expected to be called by objects within the
 * public facing layer. The objects in this private layer still need security
 * (otherwise they would be public methods) and they also need security in
 * such a manner that prevents them being called directly by external callers.
 * The objects in the private layer would be configured to require granted
 * authorities never granted to external callers. The
 * <code>RunAsManager</code> interface provides a mechanism to elevate
 * security in this manner.
 * </p>
 * 
 * <p>
 * It is expected implementations will provide a corresponding concrete
 * <code>Authentication</code> and <code>AuthenticationProvider</code> so that
 * the replacement <code>Authentication</code> object can be  authenticated.
 * Some form of security will need to be implemented to prevent to ensure the
 * <code>AuthenticationProvider</code> only accepts
 * <code>Authentication</code> objects created by an authorized concrete
 * implementation of <code>RunAsManager</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface RunAsManager {
    //~ Methods ================================================================

    /**
     * Returns a replacement <code>Authentication</code> object for the current
     * method invocation, or <code>null</code> if replacement not required.
     *
     * @param authentication the caller invoking the method
     * @param invocation the method being called
     * @param config the configuration attributes associated with the method
     *        being invoked
     *
     * @return a replacement object to be used for duration of the method
     *         invocation
     */
    public Authentication buildRunAs(Authentication authentication,
                                     MethodInvocation invocation,
                                     ConfigAttributeDefinition config);

    /**
     * Indicates whether this <code>RunAsManager</code> is able to process the
     * passed <code>ConfigAttribute</code>.
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
     * @return true if this <code>RunAsManager</code> can support the passed
     *         configuration attribute
     */
    public boolean supports(ConfigAttribute attribute);
}
