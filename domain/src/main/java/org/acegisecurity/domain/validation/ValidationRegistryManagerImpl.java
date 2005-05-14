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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

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
 * <p>If more than one <code>Validator</code> can support a given object, the
 * supporting <code>Validator</code>s will be iterated and their bean factory
 * defined bean names will be used to attempt to select the "best matching"
 * <code>Validator</code>. The lowercase version of a given object's simplified
 * class name will be searched within the bean names. If more than one
 * <code>Validator</code> contains this search criteria, an exception will be
 * thrown as the actual intended <code>Validator</code> is unidentifiable.
 * 
 * <p>For example, say you had a PartyValidator which could validate
 * com.foo.Party, and also its subclass, com.foo.Person. There is also a
 * PersonValidator which can only validate Person. PartyValidator and
 * PersonValidator are registered in the bean container as "partyValidator"
 * and "personValidator". When <code>ValidationRegistryManagerImpl</code>
 * is asked to return the <code>Validator</code> for Person, it will locate
 * the two matching <code>Validator</code>s in the bean container. As there
 * are two matching, it will look at the lowercase representation of the
 * bean names and see if either contain the lower simplified class name of
 * the object being search for (com.foo.Person thus becomes simply "person").
 * <code>ValidationRegistryManagerImpl</code> will then correctly return the
 * PersonValidator for Person. If the PartyValidator had been registered with
 * an ambiguous bean name of say "personAndPartyValidator", both bean names
 * would have matched and an exception would have been thrown.
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
		
		// Search all Validators for those that support the class
		Set<String> candidateValidatorNames = new HashSet<String>();
		Iterator<String> iter = beans.keySet().iterator();
		while (iter.hasNext()) {
			String beanName = iter.next();
			Validator validator = beans.get(beanName);
			if (validator.supports(domainClass)) {
				candidateValidatorNames.add(beanName);
			}
		}
		
		if (candidateValidatorNames.size() == 0) {
			// No Validator found
			this.validatorMap.put(domainClass, null);
			return null;
		} else if (candidateValidatorNames.size() == 1) {
			// Only one Validator found, so return it
			String validator = candidateValidatorNames.iterator().next();
			this.validatorMap.put(domainClass, validator);
			return beans.get(validator);
		} else {
			// Try to locate an entry with simple class name in it
			Iterator<String> iterCandidates = candidateValidatorNames.iterator();
			String lastFound = null;
			int numberFound = 0;
			while (iterCandidates.hasNext()) {
				String candidate = iterCandidates.next();
				if (candidate.toLowerCase().contains(domainClass.getSimpleName().toLowerCase())) {
					numberFound++;
					lastFound = candidate;
				}
			}
			if (numberFound != 1) {
				throw new IllegalArgumentException("More than one Validator found that supports '" + domainClass + "' and cannot determine most specific Validator to use; give a hint by making bean name include the simple name of the target class");
			}
			this.validatorMap.put(domainClass, lastFound);
			return beans.get(lastFound);
		}
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
