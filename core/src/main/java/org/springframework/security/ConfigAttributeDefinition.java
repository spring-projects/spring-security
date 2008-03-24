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

package org.springframework.security;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.springframework.util.Assert;


/**
 * Holds a group of {@link ConfigAttribute}s that are associated with a given secure object target - effectively a
 * Collection<ConfigAttribute>.
 * <p>
 * Once created, the object is immutable.
 * <p>
 * All the <code>ConfigAttributeDefinition</code>s associated with a given {@link
 * org.springframework.security.intercept.AbstractSecurityInterceptor} are stored in an {@link
 * org.springframework.security.intercept.ObjectDefinitionSource}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConfigAttributeDefinition implements Serializable {
    public static final ConfigAttributeDefinition NO_ATTRIBUTES = new ConfigAttributeDefinition();

    //~ Instance fields ================================================================================================

    private List configAttributes;

    //~ Constructors ===================================================================================================

    private ConfigAttributeDefinition() {
        configAttributes = Collections.EMPTY_LIST;
    }

    /**
     * Creates a ConfigAttributeDefinition containing a single attribute
     * @param attribute the String name of the attribute (converted internally to a <tt>SecurityConfig</tt> instance).
     */
    public ConfigAttributeDefinition(String attribute) {
        configAttributes = new ArrayList(1);
        configAttributes.add(new SecurityConfig(attribute));
        configAttributes = Collections.unmodifiableList(configAttributes);
    }

    /**
     * Creates a ConfigAttributeDefinition containing a single attribute.
     */
    public ConfigAttributeDefinition(ConfigAttribute attribute) {
        configAttributes = new ArrayList(1);
        configAttributes.add(attribute);
        configAttributes = Collections.unmodifiableList(configAttributes);        
    }

    /**
     * Builds a collection of ConfigAttributes from an array of String tokens, each of which will be wrapped in a
     * <tt>SecurityConfig</tt> instance.
     *
     * @param attributeTokens the tokens which will be turned into attributes.
     */
    public ConfigAttributeDefinition(String[] attributeTokens) {
        configAttributes = new ArrayList(attributeTokens.length);
        
        for (int i = 0; i < attributeTokens.length; i++) {
            configAttributes.add(new SecurityConfig(attributeTokens[i].trim()));
        }

        configAttributes = Collections.unmodifiableList(configAttributes);
    }

    /**
     * Creates an immutable ConfigAttributeDefinition from the supplied list of <tt>ConfigAttribute</tt> objects.
     */
    public ConfigAttributeDefinition(List configAttributes) {
        Iterator attributes = configAttributes.iterator();
        while (attributes.hasNext()) {
            Assert.isInstanceOf(ConfigAttribute.class, attributes.next(),
                    "List entries must be of type ConfigAttribute");
        }

        this.configAttributes = Collections.unmodifiableList(new ArrayList(configAttributes));
    }
    
    /**
     * Creates a <tt>ConfigAttributeDefinition</tt> by including only those attributes which implement <tt>ConfigAttribute</tt>.
     * 
     * @param unfilteredInput a collection of various elements, zero or more which implement <tt>ConfigAttribute</tt> (can also be <tt>null</tt>)
     * @return a ConfigAttributeDefinition if at least one <tt>ConfigAttribute</tt> was present, or <tt>null</tt> if none implemented it
     */
    public static ConfigAttributeDefinition createFiltered(Collection unfilteredInput) {
    	if (unfilteredInput == null) {
    		return null;
    	}

    	List configAttributes = new ArrayList();
    	Iterator i = unfilteredInput.iterator();
    	while (i.hasNext()) {
    		Object element = i.next();
    		if (element instanceof ConfigAttribute) {
    			configAttributes.add(element);
    		}
    	}
    	
    	if (configAttributes.size() == 0) {
    		return null;
    	}
    	
    	return new ConfigAttributeDefinition(configAttributes);
    }

    //~ Methods ========================================================================================================

    /**
     * Indicates whether the specified <code>ConfigAttribute</code> is contained within this
     * <code>ConfigAttributeDefinition</code>.
     *
     * @param configAttribute the attribute to locate
     *
     * @return <code>true</code> if the specified <code>ConfigAttribute</code> is contained, <code>false</code>
     *         otherwise
     */
    public boolean contains(ConfigAttribute configAttribute) {
        return configAttributes.contains(configAttribute);
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof ConfigAttributeDefinition)) {
            return false;
        }

        ConfigAttributeDefinition test = (ConfigAttributeDefinition) obj;

        return configAttributes.equals(test.configAttributes);
    }

    /**
     * Returns the internal collection of <code>ConfigAttribute</code>s defined by this
     * <code>ConfigAttributeDefinition</code>.
     * <p>
     * Allows <code>AccessDecisionManager</code>s and other classes to loop through every configuration attribute
     * associated with a target secure object.
     *
     * @return all the configuration attributes stored by the instance, or <code>null</code> if an
     *         <code>Iterator</code> is unavailable
     */
    public Collection getConfigAttributes() {
        return this.configAttributes;
    }

    public String toString() {
        return this.configAttributes.toString();
    }
}
