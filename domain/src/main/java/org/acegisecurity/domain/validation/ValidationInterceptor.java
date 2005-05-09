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

import net.sf.acegisecurity.domain.PersistableEntity;
import net.sf.acegisecurity.domain.impl.BusinessObject;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;


/**
 * Calls {@link ValidationManager} for method invocations.
 * 
 * <p>
 * For each method invocation, any argument that is assignable from {@link
 * #argumentClasses} <b>and</b> is non-<code>null</code> will be passed to the
 * {@link net.sf.acegisecurity.domain.validation.ValidationManager} for
 * processing.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ValidationInterceptor implements MethodInterceptor,
    InitializingBean {
    //~ Instance fields ========================================================

    protected final Log logger = LogFactory.getLog(getClass());
    private ValidationManager validationManager;
    private Class<?>[] argumentClasses = {BusinessObject.class, PersistableEntity.class};

    //~ Methods ================================================================

    public void setArgumentClasses(Class[] argumentClasses) {
        this.argumentClasses = argumentClasses;
    }

    public Class[] getArgumentClasses() {
        return argumentClasses;
    }

    public void setValidationManager(ValidationManager validationManager) {
        this.validationManager = validationManager;
    }

    public ValidationManager getValidationManager() {
        return validationManager;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(validationManager, "A ValidationManager is required");
        Assert.notEmpty(argumentClasses,
            "A list of business object classes to validate is required");
    }

    public Object invoke(MethodInvocation mi) throws Throwable {
        Object[] args = mi.getArguments();

        for (int i = 0; i < args.length; i++) {
            if (shouldValidate(args[i])) {
                if (logger.isDebugEnabled()) {
                    logger.debug("ValidationInterceptor calling for: '"
                        + args[i] + "'");
                }

                validationManager.validate(args[i]);
            }
        }

        return mi.proceed();
    }

    private boolean shouldValidate(Object argument) {
        if (argument == null) {
            return false;
        }

        for (int i = 0; i < argumentClasses.length; i++) {
            if (argumentClasses[i].isAssignableFrom(argument.getClass())) {
                return true;
            }
        }

        return false;
    }
}
