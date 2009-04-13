/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.access.intercept;

import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * Reviews the <code>Object</code> returned from a secure object invocation,
 * being able to modify the <code>Object</code> or throw an {@link
 * AccessDeniedException}.
 *
 * <p>
 * Typically used to ensure the principal is permitted to access the domain
 * object instance returned by a service layer bean. Can also be used to
 * mutate the domain object instance so the principal is only able to access
 * authorised bean properties or <code>Collection</code> elements. Often used
 * in conjunction with an {@link org.springframework.security.acl.AclManager} to
 * obtain the access control list applicable for the domain object instance.
 * </p>
 *
 * <p>
 * Special consideration should be given to using an
 * <code>AfterInvocationManager</code> on bean methods that modify a database.
 * Typically an <code>AfterInvocationManager</code> is used with read-only
 * methods, such as <code>public DomainObject getById(id)</code>. If used with
 * methods that modify a database, a transaction manager should be used to
 * ensure any <code>AccessDeniedException</code> will cause a rollback of the
 * changes made by the transaction.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AfterInvocationManager {
    //~ Methods ========================================================================================================

    /**
     * Given the details of a secure object invocation including its returned <code>Object</code>, make an
     * access control decision or optionally modify the returned <code>Object</code>.
     *
     * @param authentication the caller that invoked the method
     * @param object the secured object that was called
     * @param config the configuration attributes associated with the secured object that was invoked
     * @param returnedObject the <code>Object</code> that was returned from the secure object invocation
     *
     * @return the <code>Object</code> that will ultimately be returned to the caller (if an implementation does not
     *         wish to modify the object to be returned to the caller, the implementation should simply return the
     *         same object it was passed by the <code>returnedObject</code> method argument)
     *
     * @throws AccessDeniedException if access is denied
     */
    Object decide(Authentication authentication, Object object, List<ConfigAttribute> config,
        Object returnedObject) throws AccessDeniedException;

    /**
     * Indicates whether this <code>AfterInvocationManager</code> is able to process "after invocation"
     * requests presented with the passed <code>ConfigAttribute</code>.<p>This allows the
     * <code>AbstractSecurityInterceptor</code> to check every configuration attribute can be consumed by the
     * configured <code>AccessDecisionManager</code> and/or <code>RunAsManager</code> and/or
     * <code>AfterInvocationManager</code>.</p>
     *
     * @param attribute a configuration attribute that has been configured against the
     *        <code>AbstractSecurityInterceptor</code>
     *
     * @return true if this <code>AfterInvocationManager</code> can support the passed configuration attribute
     */
    boolean supports(ConfigAttribute attribute);

    /**
     * Indicates whether the <code>AfterInvocationManager</code> implementation is able to provide access
     * control decisions for the indicated secured object type.
     *
     * @param clazz the class that is being queried
     *
     * @return <code>true</code> if the implementation can process the indicated class
     */
    boolean supports(Class<?> clazz);
}
