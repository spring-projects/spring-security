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

package org.springframework.security.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.method.AbstractFallbackMethodDefinitionSource;


/**
 * Sources method security metadata from major JSR 250 security annotations. 
 *
 * @author Ben Alex
 * @version $Id$
 */
public class Jsr250MethodDefinitionSource extends AbstractFallbackMethodDefinitionSource {

	protected ConfigAttributeDefinition findAttributes(Class clazz) {
		return processAnnotations(clazz.getAnnotations());
	}

	protected ConfigAttributeDefinition findAttributes(Method method, Class targetClass) {
		return processAnnotations(AnnotationUtils.getAnnotations(method));
	}
	
    public Collection getConfigAttributeDefinitions() {
        return null;
    }
    
	private ConfigAttributeDefinition processAnnotations(Annotation[] annotations) {
		if (annotations == null || annotations.length == 0) {
			return null;
		}
		for (Annotation a: annotations) {
			if (a instanceof DenyAll) {
				return new ConfigAttributeDefinition(Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE);
			}
			if (a instanceof PermitAll) {
				return new ConfigAttributeDefinition(Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE);
			}
			if (a instanceof RolesAllowed) {
				RolesAllowed ra = (RolesAllowed) a;
				List attributes = new ArrayList();
				for (String allowed : ra.value()) {
					attributes.add(new Jsr250SecurityConfig(allowed));
				}
				return new ConfigAttributeDefinition(attributes);
			}
		}
		return null;
	}
}
