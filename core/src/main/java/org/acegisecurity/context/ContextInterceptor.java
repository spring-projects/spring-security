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

package net.sf.acegisecurity.context;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Ensures the {@link ContextHolder} contains a valid {@link Context}.
 * 
 * <p>
 * This interceptor works by calling {@link Context#validate()} before
 * proceeding with method invocations. It is configured in the bean context
 * with a <code>ProxyFactoryBean</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see Context#validate()
 */
public class ContextInterceptor implements MethodInterceptor {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(ContextInterceptor.class);

    //~ Methods ================================================================

    public Object invoke(MethodInvocation mi) throws Throwable {
        if (ContextHolder.getContext() == null) {
            throw new ContextHolderEmptyException("ContextHolder does not contain a Context",
                null);
        }

        ContextHolder.getContext().validate();

        Object ret = mi.proceed();

        return ret;
    }
}
