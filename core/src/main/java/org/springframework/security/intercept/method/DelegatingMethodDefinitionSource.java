package org.springframework.security.intercept.method;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.util.Assert;

/**
 * Automatically tries a series of method definition sources, relying on the first source of metadata
 * that provides a non-null response.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public final class DelegatingMethodDefinitionSource implements MethodDefinitionSource, InitializingBean {
	private List methodDefinitionSources;
	
	public void afterPropertiesSet() throws Exception {
		Assert.notEmpty(methodDefinitionSources, "A list of MethodDefinitionSources is required");
	}

	public ConfigAttributeDefinition getAttributes(Method method, Class targetClass) {
		Iterator i = methodDefinitionSources.iterator();
		while (i.hasNext()) {
			MethodDefinitionSource s = (MethodDefinitionSource) i.next();
			ConfigAttributeDefinition result = s.getAttributes(method, targetClass);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	public ConfigAttributeDefinition getAttributes(Object object) throws IllegalArgumentException {
		Iterator i = methodDefinitionSources.iterator();
		while (i.hasNext()) {
			MethodDefinitionSource s = (MethodDefinitionSource) i.next();
			ConfigAttributeDefinition result = s.getAttributes(object);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	public Collection getConfigAttributeDefinitions() {
		Set set = new HashSet();
		Iterator i = methodDefinitionSources.iterator();
		while (i.hasNext()) {
			MethodDefinitionSource s = (MethodDefinitionSource) i.next();
			Collection attrs = s.getConfigAttributeDefinitions();
			if (attrs != null) {
				set.addAll(attrs);
			}
		}
		return set;
	}

	public boolean supports(Class clazz) {
		Iterator i = methodDefinitionSources.iterator();
		while (i.hasNext()) {
			MethodDefinitionSource s = (MethodDefinitionSource) i.next();
			if (s.supports(clazz)) {
				return true;
			}
		}
		return false;
	}

	public void setMethodDefinitionSources(List methodDefinitionSources) {
		Assert.notEmpty(methodDefinitionSources, "A list of MethodDefinitionSources is required");
		this.methodDefinitionSources = methodDefinitionSources;
	}
}
