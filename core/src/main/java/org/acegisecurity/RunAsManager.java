/* Copyright 2004, 2005 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity;

/**
 * Creates a new temporary {@link Authentication} object for the current secure
 * object invocation only.
 * 
 * <p>
 * This interface permits implementations to replace the
 * <code>Authentication</code> object that applies to the current secure
 * object invocation only. The {@link
 * net.sf.acegisecurity.intercept.AbstractSecurityInterceptor} will replace
 * the <code>Authentication</code> object held in the
 * {@link net.sf.acegisecurity.context.SecurityContext SecurityContext}
 * for the duration of  the secure object callback only, returning it to
 * the original <code>Authentication</code> object when the callback ends.
 * </p>
 * 
 * <p>
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
 * the replacement <code>Authentication</code> object can be authenticated.
 * Some form of security will need to be implemented to ensure the
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
     * secure object invocation, or <code>null</code> if replacement not
     * required.
     *
     * @param authentication the caller invoking the secure object
     * @param object the secured object being called
     * @param config the configuration attributes associated with the secure
     *        object being invoked
     *
     * @return a replacement object to be used for duration of the secure
     *         object invocation, or <code>null</code> if the
     *         <code>Authentication</code> should be left as is
     */
    public Authentication buildRunAs(Authentication authentication,
        Object object, ConfigAttributeDefinition config);

    /**
     * Indicates whether this <code>RunAsManager</code> is able to process the
     * passed <code>ConfigAttribute</code>.
     * 
     * <p>
     * This allows the <code>AbstractSecurityInterceptor</code> to check every
     * configuration attribute can be consumed by the configured
     * <code>AccessDecisionManager</code> and/or <code>RunAsManager</code>
     * and/or <code>AfterInvocationManager</code>.
     * </p>
     *
     * @param attribute a configuration attribute that has been configured
     *        against the <code>AbstractSecurityInterceptor</code>
     *
     * @return <code>true</code> if this <code>RunAsManager</code> can support
     *         the passed configuration attribute
     */
    public boolean supports(ConfigAttribute attribute);

    /**
     * Indicates whether the <code>RunAsManager</code> implementation is able
     * to provide run-as replacement for the indicated secure object type.
     *
     * @param clazz the class that is being queried
     *
     * @return true if the implementation can process the indicated class
     */
    public boolean supports(Class clazz);
}
