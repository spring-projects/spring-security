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

import java.util.Iterator;
import java.util.List;
import java.util.Vector;


/**
 * Holds a group of {@link ConfigAttribute}s that are associated with a given secure object target.<p>All the
 * <code>ConfigAttributeDefinition</code>s associated with a given {@link
 * org.springframework.security.intercept.AbstractSecurityInterceptor} are stored in an {@link
 * org.springframework.security.intercept.ObjectDefinitionSource}.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConfigAttributeDefinition implements Serializable {
    //~ Instance fields ================================================================================================

    private List configAttributes = new Vector();

    //~ Constructors ===================================================================================================

    public ConfigAttributeDefinition() {
        super();
    }

    //~ Methods ========================================================================================================

    /**
     * Adds a <code>ConfigAttribute</code> that is related to the secure object method.
     *
     * @param newConfigAttribute the new configuration attribute to add
     */
    public void addConfigAttribute(ConfigAttribute newConfigAttribute) {
        this.configAttributes.add(newConfigAttribute);
    }

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
        if (obj instanceof ConfigAttributeDefinition) {
            ConfigAttributeDefinition test = (ConfigAttributeDefinition) obj;

            List testAttrs = new Vector();
            Iterator iter = test.getConfigAttributes();

            while (iter.hasNext()) {
                ConfigAttribute attr = (ConfigAttribute) iter.next();
                testAttrs.add(attr);
            }

            if (this.configAttributes.size() != testAttrs.size()) {
                return false;
            }

            for (int i = 0; i < this.configAttributes.size(); i++) {
                if (!this.configAttributes.get(i).equals(testAttrs.get(i))) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Returns an <code>Iterator</code> over all the <code>ConfigAttribute</code>s defined by this
     * <code>ConfigAttributeDefinition</code>.<P>Allows <code>AccessDecisionManager</code>s and other classes
     * to loop through every configuration attribute associated with a target secure object.</p>
     *
     * @return all the configuration attributes stored by the instance, or <code>null</code> if an
     *         <code>Iterator</code> is unavailable
     */
    public Iterator getConfigAttributes() {
        return this.configAttributes.iterator();
    }

    /**
     * Returns the number of <code>ConfigAttribute</code>s defined by this
     * <code>ConfigAttributeDefinition</code>.
     *
     * @return the number of <code>ConfigAttribute</code>s contained
     */
    public int size() {
        return configAttributes.size();
    }

    public String toString() {
        return this.configAttributes.toString();
    }
}
