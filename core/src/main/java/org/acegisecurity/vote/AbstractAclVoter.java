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

package org.acegisecurity.vote;

import org.acegisecurity.AuthorizationServiceException;
import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.acl.AclEntry;
import org.acegisecurity.acl.AclManager;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.util.Assert;

import java.lang.reflect.Method;


/**
 * <p>
 * Given a domain object instance passed as a method argument, ensures the
 * principal has appropriate permission as defined by the {@link AclManager}.
 * </p>
 * 
 * <p>
 * The <code>AclManager</code> is used to retrieve the access control list
 * (ACL) permissions associated with a domain object instance for the current
 * <code>Authentication</code> object. This class is designed to process
 * {@link AclEntry}s that are subclasses of {@link
 * org.acegisecurity.acl.basic.BasicAclEntry} only. Generally these are
 * obtained by using the {@link
 * org.acegisecurity.acl.basic.BasicAclProvider}.
 * </p>
 * 
 * <p>
 * The voter will vote if any  {@link ConfigAttribute#getAttribute()} matches
 * the {@link #processConfigAttribute}. The provider will then locate the
 * first method argument of type {@link #processDomainObjectClass}. Assuming
 * that method argument is non-null, the provider will then lookup the ACLs
 * from the <code>AclManager</code> and ensure the principal is {@link
 * org.acegisecurity.acl.basic.BasicAclEntry#isPermitted(int)} for at least
 * one of the {@link #requirePermission}s.
 * </p>
 * 
 * <p>
 * If the method argument is <code>null</code>, the voter will abstain from
 * voting. If the method argument could not be found, an {@link
 * org.acegisecurity.AuthorizationServiceException} will be thrown.
 * </p>
 * 
 * <p>
 * In practical terms users will typically setup a number of
 * <code>BasicAclEntryVoter</code>s. Each will have a different {@link
 * #processDomainObjectClass}, {@link #processConfigAttribute} and {@link
 * #requirePermission} combination. For example, a small application might
 * employ the following instances of <code>BasicAclEntryVoter</code>:
 * 
 * <ul>
 * <li>
 * Process domain object class <code>BankAccount</code>, configuration
 * attribute <code>VOTE_ACL_BANK_ACCONT_READ</code>, require permission
 * <code>SimpleAclEntry.READ</code>
 * </li>
 * <li>
 * Process domain object class <code>BankAccount</code>, configuration
 * attribute <code>VOTE_ACL_BANK_ACCOUNT_WRITE</code>, require permission list
 * <code>SimpleAclEntry.WRITE</code> and <code>SimpleAclEntry.CREATE</code>
 * (allowing the principal to have <b>either</b> of these two permissions
 * </li>
 * <li>
 * Process domain object class <code>Customer</code>, configuration attribute
 * <code>VOTE_ACL_CUSTOMER_READ</code>, require permission
 * <code>SimpleAclEntry.READ</code>
 * </li>
 * <li>
 * Process domain object class <code>Customer</code>, configuration attribute
 * <code>VOTE_ACL_CUSTOMER_WRITE</code>, require permission list
 * <code>SimpleAclEntry.WRITE</code> and <code>SimpleAclEntry.CREATE</code>
 * </li>
 * </ul>
 * 
 * Alternatively, you could have used a common superclass or interface for the
 * {@link #processDomainObjectClass} if both <code>BankAccount</code> and
 * <code>Customer</code> had common parents.
 * </p>
 * 
 * <p>
 * If the principal does not have sufficient permissions, the voter will vote
 * to deny access.
 * </p>
 * 
 * <p>
 * The <code>AclManager</code> is allowed to return any implementations of
 * <code>AclEntry</code> it wishes. However, this provider will only be able
 * to validate against <code>AbstractBasicAclEntry</code>s, and thus a vote to
 * deny access will be made if no <code>AclEntry</code> is of type
 * <code>AbstractBasicAclEntry</code>.
 * </p>
 * 
 * <p>
 * All comparisons and prefixes are case sensitive.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractAclVoter implements AccessDecisionVoter {
    //~ Instance fields ========================================================

    private Class processDomainObjectClass;

    //~ Methods ================================================================

    public void setProcessDomainObjectClass(Class processDomainObjectClass) {
        Assert.notNull(processDomainObjectClass,
            "processDomainObjectClass cannot be set to null");
        this.processDomainObjectClass = processDomainObjectClass;
    }

    public Class getProcessDomainObjectClass() {
        return processDomainObjectClass;
    }

    /**
     * This implementation supports only
     * <code>MethodSecurityInterceptor</code>, because it queries the
     * presented <code>MethodInvocation</code>.
     *
     * @param clazz the secure object
     *
     * @return <code>true</code> if the secure object is
     *         <code>MethodInvocation</code>, <code>false</code> otherwise
     */
    public boolean supports(Class clazz) {
        return (MethodInvocation.class.isAssignableFrom(clazz));
    }

    protected Object getDomainObjectInstance(Object secureObject) {
        MethodInvocation invocation = (MethodInvocation) secureObject;

        // Check if this MethodInvocation provides the required argument
        Method method = invocation.getMethod();
        Class[] params = method.getParameterTypes();

        for (int i = 0; i < params.length; i++) {
            if (processDomainObjectClass.isAssignableFrom(params[i])) {
                return invocation.getArguments()[i];
            }
        }

        throw new AuthorizationServiceException("MethodInvocation: "
            + invocation + " did not provide any argument of type: "
            + processDomainObjectClass);
    }
}
