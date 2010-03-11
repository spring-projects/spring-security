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

package org.springframework.security.access.method;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.lang.JoinPoint;
import org.springframework.security.access.ConfigAttribute;


/**
 * Abstract implementation of <tt>MethodSecurityMetadataSource</tt> which resolves the secured object type to
 * either a MethodInvocation or a JoinPoint.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public abstract class AbstractMethodSecurityMetadataSource implements MethodSecurityMetadataSource {

    protected final Log logger = LogFactory.getLog(getClass());

    //~ Methods ========================================================================================================

    public final Collection<ConfigAttribute> getAttributes(Object object) {
        if (object instanceof MethodInvocation) {
            MethodInvocation mi = (MethodInvocation) object;
            Object target = mi.getThis();
            Class<?> targetClass = null;

            if (target != null) {
                targetClass = target instanceof Class<?> ? (Class<?>)target : target.getClass();
            }

            return getAttributes(mi.getMethod(), targetClass);
        }

        throw new IllegalArgumentException("Object must be a non-null MethodInvocation");
    }

    public final boolean supports(Class<?> clazz) {
        return (MethodInvocation.class.isAssignableFrom(clazz) || JoinPoint.class.isAssignableFrom(clazz));
    }
}
