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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;

import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import org.springframework.validation.Validator;

import java.util.HashMap;
import java.util.Map;


/**
 * A basic implementation of {@link ValidationRegistryManager}.
 * 
 * <p>
 * Like <a
 * href="http://java.sun.com/j2se/1.4.2/docs/api/java/beans/PropertyEditorManager.html">PropertyEditorManager</a>,
 * this implementation uses three techniques for locating a
 * <code>Validator</code> for a given domain object class:
 * 
 * <ol>
 * <li>
 * First, the {@link #registerValidator(Class, Class)} method allows a
 * <code>Validator</code> to be expressly registered for a given domain object
 * class.
 * </li>
 * <li>
 * Second, an attempt will be made to find the <code>Validator</code> by
 * concatenating "Validator" to the fully qualified domain object classname
 * (eg "foo.bah.PersonValidator").
 * </li>
 * <li>
 * Third, it takes the domain object's simple classname (without the package
 * name), adds "Validator" to it, then looks in the {@link
 * #validatorSearchPath} for the validator.
 * </li>
 * </ol>
 * </p>
 *
 * @author Matthew E. Porter
 * @author Ben Alex
 * @version $Id$
 */
public class ValidationRegistryManagerImpl implements ValidationRegistryManager,
    BeanFactoryAware {
    //~ Static fields/initializers =============================================

    private static final String VALIDATOR_SUFFIX = "Validator";

    //~ Instance fields ========================================================

    private AutowireCapableBeanFactory acbf;
    private Map validatorMap = new HashMap();
    private String[] validatorSearchPath;

    //~ Methods ================================================================

    public void setBeanFactory(BeanFactory beanFactory)
        throws BeansException {
        Assert.isInstanceOf(AutowireCapableBeanFactory.class, beanFactory,
            "BeanFactory must be AutowireCapableBeanFactory");
        this.acbf = (AutowireCapableBeanFactory) beanFactory;
    }

    public void setValidatorSearchPath(String[] validatorSearchPath) {
        this.validatorSearchPath = validatorSearchPath;
    }

    public String[] getValidatorSearchPath() {
        return validatorSearchPath;
    }

    public Validator findValidator(Class domainClass) {
        Assert.notNull(domainClass, "domainClass cannot be null");

        Class validatorClass = null;
        Validator validator = null;

        if (validatorMap.containsKey(domainClass)) {
            // already known to our Map
            validatorClass = (Class) validatorMap.get(domainClass);
        } else {
            validatorClass = this.findValidatorClass(domainClass.getName()
                    + VALIDATOR_SUFFIX);

            if (validatorClass == null) {
                String suffix = "." + ClassUtils.getShortName(domainClass)
                    + VALIDATOR_SUFFIX;

                if (validatorSearchPath != null) {
                    for (int i = 0;
                        (i < validatorSearchPath.length)
                        && (validatorClass == null); i++) {
                        validatorClass = this.findValidatorClass(validatorSearchPath[i]
                                + suffix);
                    }
                }
            }

            // if we found a Validator, register it so we speed up future retrieval
            if (validatorClass != null) {
                this.registerValidator(domainClass, validatorClass);
            }
        }

        // Attempt to create an instance of the Validator
        if (validatorClass != null) {
            validator = obtainWiredValidator(validatorClass);
        }

        return validator;
    }

    public void registerValidator(Class domainClass, Class validatorClass) {
        Assert.notNull(domainClass, "domainClass cannot be null");
        Assert.notNull(validatorClass, "validatorClass cannot be null");
        Assert.isTrue(Validator.class.isAssignableFrom(validatorClass),
            "validatorClass must be an implementation of Validator");
        this.validatorMap.put(domainClass, validatorClass);
    }

    /**
     * Builds a new instance of the <code>Validator</code>.
     * 
     * <p>
     * By default, the <code>AutowireCapableBeanFactory</code> is used to build
     * the instance, and autowire its bean properties. Specialised
     * applications may wish to customise this behaviour, such as searching
     * through the <code>ApplicationContext</code> for an existing singleton
     * instance. This method is protected to enable such customisation.
     * </p>
     *
     * @param clazz the represents the <code>Validator</code> instance required
     *
     * @return the requested <code>Validator</code>, fully wired with all
     *         dependencies, or <code>null</code> if the
     *         <code>Validator</code> could not be found or created
     */
    protected Validator obtainWiredValidator(Class clazz) {
        try {
            return (Validator) this.acbf.autowire(clazz,
                AutowireCapableBeanFactory.AUTOWIRE_BY_TYPE, false);
        } catch (BeansException autowireFailure) {
            return null;
        }
    }

    private Class findValidatorClass(String validatorClassName) {
        Class validatorClass = null;

        try {
            ClassLoader contextClassLoader = Thread.currentThread()
                                                   .getContextClassLoader();
            validatorClass = Class.forName(validatorClassName);
        } catch (ClassNotFoundException e) {}

        return validatorClass;
    }
}
