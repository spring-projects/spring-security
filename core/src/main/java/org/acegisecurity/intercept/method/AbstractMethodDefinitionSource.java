/* Copyright 2004 Acegi Technology Pty Limited
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

package org.acegisecurity.intercept.method;

import org.acegisecurity.ConfigAttributeDefinition;

import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.CodeSignature;
import org.springframework.util.Assert;

import java.lang.reflect.Method;


/**
 * Abstract implementation of <Code>MethodDefinitionSource</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractMethodDefinitionSource
    implements MethodDefinitionSource {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(AbstractMethodDefinitionSource.class);

    //~ Methods ================================================================

    public ConfigAttributeDefinition getAttributes(Object object)
        throws IllegalArgumentException {
        Assert.notNull(object, "Object cannot be null");

        if (object instanceof MethodInvocation) {
            return this.lookupAttributes(((MethodInvocation) object).getMethod());
        }

        if (object instanceof JoinPoint) {
            JoinPoint jp = (JoinPoint) object;
            Class targetClazz = jp.getTarget().getClass();
            String targetMethodName = jp.getStaticPart().getSignature().getName();
            Class[] types = ((CodeSignature) jp.getStaticPart().getSignature())
                    .getParameterTypes();

            if (logger.isDebugEnabled()) {
                logger.debug("Target Class: " + targetClazz);
                logger.debug("Target Method Name: " + targetMethodName);

                for (int i = 0; i < types.length; i++) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Target Method Arg #" + i + ": "
                                + types[i]);
                    }
                }
            }

            try {
                return this.lookupAttributes(targetClazz.getMethod(targetMethodName, types));
            } catch (NoSuchMethodException nsme) {
                throw new IllegalArgumentException("Could not obtain target method from JoinPoint: " + jp);
            }
        }

        throw new IllegalArgumentException("Object must be a MethodInvocation or JoinPoint");
    }

    public boolean supports(Class clazz) {
        return (MethodInvocation.class.isAssignableFrom(clazz)
        || JoinPoint.class.isAssignableFrom(clazz));
    }

    /**
     * Performs the actual lookup of the relevant
     * <code>ConfigAttributeDefinition</code> for the specified
     * <code>Method</code> which is subject of the method invocation.
     * 
     * <P>
     * Provided so subclasses need only to provide one basic method to properly
     * interface with the <code>MethodDefinitionSource</code>.
     * </p>
     * 
     * <p>
     * Returns <code>null</code> if there are no matching attributes for the
     * method.
     * </p>
     *
     * @param method the method being invoked for which configuration
     *        attributes should be looked up
     *
     * @return the <code>ConfigAttributeDefinition</code> that applies to the
     *         specified <code>Method</code>
     */
    protected abstract ConfigAttributeDefinition lookupAttributes(Method method);
}
