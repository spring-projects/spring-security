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
package org.acegisecurity.vote;

import org.acegisecurity.AuthorizationServiceException;

import org.aopalliance.intercept.MethodInvocation;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.CodeSignature;

import org.springframework.util.Assert;


/**
 * <p>Provides helper methods for writing domain object ACL voters. Is not bound to any particular ACL system.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractAclVoter implements AccessDecisionVoter {
    //~ Instance fields ================================================================================================

    private Class processDomainObjectClass;

    //~ Methods ========================================================================================================

    protected Object getDomainObjectInstance(Object secureObject) {
        Object[] args;
        Class[] params;

        if (secureObject instanceof MethodInvocation) {
            MethodInvocation invocation = (MethodInvocation) secureObject;
            params = invocation.getMethod().getParameterTypes();
            args = invocation.getArguments();
        } else {
            JoinPoint jp = (JoinPoint) secureObject;
            params = ((CodeSignature) jp.getStaticPart().getSignature()).getParameterTypes();
            args = jp.getArgs();
        }

        for (int i = 0; i < params.length; i++) {
            if (processDomainObjectClass.isAssignableFrom(params[i])) {
                return args[i];
            }
        }

        throw new AuthorizationServiceException("Secure object: " + secureObject
            + " did not provide any argument of type: " + processDomainObjectClass);
    }

    public Class getProcessDomainObjectClass() {
        return processDomainObjectClass;
    }

    public void setProcessDomainObjectClass(Class processDomainObjectClass) {
        Assert.notNull(processDomainObjectClass, "processDomainObjectClass cannot be set to null");
        this.processDomainObjectClass = processDomainObjectClass;
    }

    /**
     * This implementation supports only <code>MethodSecurityInterceptor</code>, because it queries the
     * presented <code>MethodInvocation</code>.
     *
     * @param clazz the secure object
     *
     * @return <code>true</code> if the secure object is <code>MethodInvocation</code>, <code>false</code> otherwise
     */
    public boolean supports(Class clazz) {
        if (MethodInvocation.class.isAssignableFrom(clazz)) {
            return true;
        } else if (JoinPoint.class.isAssignableFrom(clazz)) {
            return true;
        } else {
            return false;
        }
    }
}
