/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;


/**
 * Holds a group of {@link ConfigAttribute}s that are associated with a given
 * method.
 * 
 * <p>
 * All the <code>ConfigAttributeDefinition</code>s associated with a given
 * <code>SecurityInterceptor</code> are stored in a  {@link
 * MethodDefinitionMap}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConfigAttributeDefinition {
    //~ Instance fields ========================================================

    private List configAttributes = new Vector();

    //~ Constructors ===========================================================

    public ConfigAttributeDefinition() {
        super();
    }

    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @return all the configuration attributes related to the method.
     */
    public Iterator getConfigAttributes() {
        return this.configAttributes.iterator();
    }

    /**
     * Adds a <code>ConfigAttribute</code> that is related to the method.
     *
     * @param newConfigAttribute DOCUMENT ME!
     */
    public void addConfigAttribute(ConfigAttribute newConfigAttribute) {
        this.configAttributes.add(newConfigAttribute);
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

    public String toString() {
        return this.configAttributes.toString();
    }
}
