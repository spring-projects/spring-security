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

import org.springframework.security.access.ConfigAttribute;

import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.CodeSignature;

import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Method;
import java.util.List;


/**
 * Abstract implementation of <tt>MethodSecurityMetadataSource</tt> which resolves the secured object type to
 * either a MethodInvocation or a JoinPoint.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractMethodSecurityMetadataSource implements MethodSecurityMetadataSource {

    protected final Log logger = LogFactory.getLog(getClass());

    //~ Methods ========================================================================================================

    public final List<ConfigAttribute> getAttributes(Object object) {
        if (object instanceof MethodInvocation) {
            MethodInvocation mi = (MethodInvocation) object;
            Object target = mi.getThis();
            return getAttributes(mi.getMethod(), target == null ? null : target.getClass());
        }

        if (object instanceof JoinPoint) {
            JoinPoint jp = (JoinPoint) object;
            Class<?> targetClass = jp.getTarget().getClass();
            String targetMethodName = jp.getStaticPart().getSignature().getName();
            Class<?>[] types = ((CodeSignature) jp.getStaticPart().getSignature()).getParameterTypes();
            Class<?> declaringType = ((CodeSignature) jp.getStaticPart().getSignature()).getDeclaringType();

            Method method = ClassUtils.getMethodIfAvailable(declaringType, targetMethodName, types);
            Assert.notNull(method, "Could not obtain target method from JoinPoint: '"+ jp + "'");

            return getAttributes(method, targetClass);
        }

        throw new IllegalArgumentException("Object must be a non-null MethodInvocation or JoinPoint");
    }

    public final boolean supports(Class<?> clazz) {
        return (MethodInvocation.class.isAssignableFrom(clazz) || JoinPoint.class.isAssignableFrom(clazz));
    }
}
