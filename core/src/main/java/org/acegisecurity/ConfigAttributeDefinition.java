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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


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

    private Set configAttributes = new HashSet();

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

    public String toString() {
        return this.configAttributes.toString();
    }
}
