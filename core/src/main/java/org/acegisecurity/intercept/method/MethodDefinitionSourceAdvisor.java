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

package net.sf.acegisecurity.intercept.method;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.framework.AopConfigException;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;


/**
 * Advisor driven by a {@link MethodDefinitionSource}, used to exclude a {@link
 * MethodSecurityInterceptor} from public (ie non-secure) methods.
 * 
 * <p>
 * Because the AOP framework caches advice calculations, this is normally
 * faster than just letting the <code>MethodSecurityInterceptor</code> run and
 * find out itself that it has no work to do.
 * </p>
 * 
 * <p>
 * This class also allows the use of Spring's
 * <code>DefaultAdvisorAutoProxyCreator</code>, which makes configuration
 * easier than setup a <code>ProxyFactoryBean</code> for each object requiring
 * security. Note that autoproxying is not supported for BeanFactory
 * implementations, as post-processing is automatic only for application
 * contexts.
 * </p>
 * 
 * <p>
 * Based on Spring's TransactionAttributeSourceAdvisor.
 * </p>
 * 
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionSourceAdvisor
    extends StaticMethodMatcherPointcutAdvisor {
    //~ Instance fields ========================================================

    private MethodDefinitionSource transactionAttributeSource;

    //~ Constructors ===========================================================

    public MethodDefinitionSourceAdvisor(MethodSecurityInterceptor advice) {
        super(advice);

        if (advice.getObjectDefinitionSource() == null) {
            throw new AopConfigException(
                "Cannot construct a MethodDefinitionSourceAdvisor using a "
                + "MethodSecurityInterceptor that has no ObjectDefinitionSource configured");
        }

        this.transactionAttributeSource = advice.getObjectDefinitionSource();
    }

    //~ Methods ================================================================

    public boolean matches(Method m, Class targetClass) {
        MethodInvocation methodInvocation = new InternalMethodInvocation(m);

        return (this.transactionAttributeSource.getAttributes(methodInvocation) != null);
    }

    //~ Inner Classes ==========================================================

    /**
     * Represents a <code>MethodInvocation</code>.
     * 
     * <p>
     * Required as <code>MethodDefinitionSource</code> only supports lookup of
     * configuration attributes for <code>MethodInvocation</code>s.
     * </p>
     */
    private class InternalMethodInvocation implements MethodInvocation {
        Method method;

        public InternalMethodInvocation(Method method) {
            this.method = method;
        }

        private InternalMethodInvocation() {}

        public Object[] getArguments() {
            throw new UnsupportedOperationException();
        }

        public Method getMethod() {
            return this.method;
        }

        public AccessibleObject getStaticPart() {
            throw new UnsupportedOperationException();
        }

        public Object getThis() {
            throw new UnsupportedOperationException();
        }

        public Object proceed() throws Throwable {
            throw new UnsupportedOperationException();
        }
    }
}
