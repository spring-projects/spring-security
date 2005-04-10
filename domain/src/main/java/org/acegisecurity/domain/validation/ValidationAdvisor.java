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

package net.sf.acegisecurity.domain.validation;

import org.springframework.aop.framework.AopConfigException;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.lang.reflect.Method;


/**
 * Advisor for the {@link ValidationInterceptor}.
 * 
 * <p>
 * Intended to be used with Spring's
 * <code>DefaultAdvisorAutoProxyCreator</code>.
 * </p>
 * 
 * <p>
 * Registers {@link ValidationInterceptor} for every <code>Method</code>
 * against a class that directly or through its superclasses implements {@link
 * #supportsClass} and has a signature match those defined by {@link
 * #methods}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ValidationAdvisor extends StaticMethodMatcherPointcutAdvisor
    implements InitializingBean {
    //~ Instance fields ========================================================

    private Class supportsClass;
    private String[] methods = {"create", "update", "createOrUpdate"};

    //~ Constructors ===========================================================

    public ValidationAdvisor(ValidationInterceptor advice) {
        super(advice);

        if (advice == null) {
            throw new AopConfigException(
                "Cannot construct a BindAndValidateAdvisor using a "
                + "null BindAndValidateInterceptor");
        }
    }

    //~ Methods ================================================================

    public void setMethods(String[] methods) {
        this.methods = methods;
    }

    public String[] getMethods() {
        return methods;
    }

    public void setSupportsClass(Class clazz) {
        this.supportsClass = clazz;
    }

    public Class getSupportsClass() {
        return supportsClass;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(supportsClass, "A supportsClass is required");
        Assert.notNull(methods, "A list of valid methods is required");
        Assert.notEmpty(methods, "A list of valid methods is required");
    }

    public boolean matches(Method m, Class targetClass) {
        // Check there are actual arguments
        if (m.getParameterTypes().length == 0) {
            return false;
        }

        // Check the method name matches one we're interested in
        boolean found = false;

        for (int i = 0; i < methods.length; i++) {
            if (m.getName().equals(methods[i])) {
                found = true;
            }
        }

        if (!found) {
            return false;
        }

        // Check the target is of the type of class we wish to advise
        if (supportsClass.isAssignableFrom(targetClass)) {
            return true;
        }

        return false;
    }
}
