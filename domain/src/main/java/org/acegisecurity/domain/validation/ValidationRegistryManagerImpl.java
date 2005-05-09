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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.util.Assert;
import org.springframework.validation.Validator;


/**
 * A basic implementation of {@link ValidationRegistryManager}.
 * 
 * <p>
 * Locates <code>Validator</code>s registered in bean factory.
 * </p>
 *
 * @author Matthew E. Porter
 * @author Ben Alex
 * @version $Id$
 */
public class ValidationRegistryManagerImpl implements ValidationRegistryManager,
    BeanFactoryAware {
    //~ Static fields/initializers =============================================

    //~ Instance fields ========================================================

    private ListableBeanFactory bf;
    private Map<Class,String> validatorMap = new HashMap<Class,String>();

    //~ Methods ================================================================

    public void setBeanFactory(BeanFactory beanFactory)
        throws BeansException {
        Assert.isInstanceOf(ListableBeanFactory.class, beanFactory,
            "BeanFactory must be ListableBeanFactory");
        this.bf = (ListableBeanFactory) beanFactory;
    }

    public Validator findValidator(Class domainClass) {
        Assert.notNull(domainClass, "domainClass cannot be null");

		if (validatorMap.containsKey(domainClass)) {
			if (validatorMap.get(domainClass) == null) {
				return null;
			}
			return (Validator) this.bf.getBean((String)validatorMap.get(domainClass), Validator.class);
		}
		
		// Attempt to find Validator via introspection
		Map<String,Validator> beans = BeanFactoryUtils.beansOfTypeIncludingAncestors(bf, Validator.class, true, true);
		Iterator<String> iter = beans.keySet().iterator();
		while (iter.hasNext()) {
			String beanName = iter.next();
			Validator validator = beans.get(beanName);
			if (validator.supports(domainClass)) {
				this.validatorMap.put(domainClass, beanName);
				return validator;
			}
		}
		
		// No Validator found
		this.validatorMap.put(domainClass, null);
		return null;
    }

    public void registerValidator(Class domainClass, String beanName) {
        Assert.notNull(domainClass, "domainClass cannot be null");
        Assert.notNull(beanName, "beanName cannot be null");
		Assert.isTrue(this.bf.containsBean(beanName), "beanName not found in context");
		Assert.isInstanceOf(Validator.class, this.bf.getBean(beanName), "beanName '" + beanName + "' must be a Validator");
        Assert.isTrue(((Validator)this.bf.getBean(beanName)).supports(domainClass), "Validator does not support " + domainClass);
		this.validatorMap.put(domainClass, beanName);
    }
}
