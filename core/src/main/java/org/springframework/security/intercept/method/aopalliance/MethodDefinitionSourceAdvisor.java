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

package org.springframework.security.intercept.method.aopalliance;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopConfigException;
import org.springframework.aop.support.AbstractPointcutAdvisor;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.security.intercept.method.MethodDefinitionSource;


/**
 * Advisor driven by a {@link MethodDefinitionSource}, used to exclude a {@link MethodSecurityInterceptor} from
 * public (ie non-secure) methods.<p>Because the AOP framework caches advice calculations, this is normally faster
 * than just letting the <code>MethodSecurityInterceptor</code> run and find out itself that it has no work to do.
 * <p>
 * This class also allows the use of Spring's
 * {@link org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator}, which makes
 * configuration easier than setup a <code>ProxyFactoryBean</code> for each object requiring security. Note that
 * autoproxying is not supported for BeanFactory implementations, as post-processing is automatic only for application
 * contexts.
 * <p>
 * Based on Spring's TransactionAttributeSourceAdvisor.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionSourceAdvisor extends AbstractPointcutAdvisor {
    //~ Instance fields ================================================================================================

    private MethodDefinitionSource attributeSource;
    private MethodSecurityInterceptor interceptor;
    private Pointcut pointcut;

    //~ Constructors ===================================================================================================

    public MethodDefinitionSourceAdvisor(MethodSecurityInterceptor advice) {
    	this.interceptor = advice;

        if (advice.getObjectDefinitionSource() == null) {
            throw new AopConfigException("Cannot construct a MethodDefinitionSourceAdvisor using a "
                + "MethodSecurityInterceptor that has no ObjectDefinitionSource configured");
        }

        this.attributeSource = advice.getObjectDefinitionSource();
        this.pointcut = new MethodDefinitionSourcePointcut();
    }

    //~ Methods ========================================================================================================

	public Pointcut getPointcut() {
		return pointcut;
	}

	public Advice getAdvice() {
		return interceptor;
	}

    //~ Inner Classes ==================================================================================================
    
    class MethodDefinitionSourcePointcut extends StaticMethodMatcherPointcut {
        public boolean matches(Method m, Class targetClass) {
            MethodInvocation methodInvocation = new InternalMethodInvocation(m);

            return attributeSource.getAttributes(methodInvocation) != null;
        }
    }
    
    /**
     * Represents a <code>MethodInvocation</code>.
     * <p>
     * Required as <code>MethodDefinitionSource</code> only supports lookup of configuration attributes for
     * <code>MethodInvocation</code>s.
     */
    class InternalMethodInvocation implements MethodInvocation {
        private Method method;

        public InternalMethodInvocation(Method method) {
            this.method = method;
        }

        protected InternalMethodInvocation() {
            throw new UnsupportedOperationException();
        }

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
