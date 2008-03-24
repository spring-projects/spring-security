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

package org.springframework.security.intercept.method;

import java.lang.reflect.Method;
import java.util.Collection;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.metadata.Attributes;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.util.Assert;


/**
 * Provides {@link ConfigAttributeDefinition}s for a method signature (via the <tt>lookupAttributes</tt> method)
 * by delegating to a configured {@link Attributes} object. The latter may use Commons attributes
 * or some other approach to determine the <tt>ConfigAttribute</tt>s which apply. 
 *
 * <p>
 * Note that attributes defined against parent classes (either for their methods or interfaces) are not
 * detected. The attributes must be defined against an explicit method or interface on the intercepted class.
 * <p>
 * 
 * Attributes detected that do not implement {@link ConfigAttribute} will be ignored.
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionAttributes extends AbstractFallbackMethodDefinitionSource implements InitializingBean {
    //~ Instance fields ================================================================================================

    private Attributes attributes;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
    	Assert.notNull(attributes, "attributes required");
	}

    public Collection getConfigAttributeDefinitions() {
        return null;
    }
    
	protected ConfigAttributeDefinition findAttributes(Class clazz) {
        return ConfigAttributeDefinition.createFiltered(attributes.getAttributes(clazz));
	}

	protected ConfigAttributeDefinition findAttributes(Method method, Class targetClass) {
        return ConfigAttributeDefinition.createFiltered(attributes.getAttributes(method));
	}

    public void setAttributes(Attributes attributes) {
    	Assert.notNull(attributes, "Attributes required");
        this.attributes = attributes;
    }
}
