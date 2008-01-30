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

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;

import java.lang.reflect.Method;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;


/**
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockMethodDefinitionSource extends AbstractMethodDefinitionSource {
    //~ Instance fields ================================================================================================

    private List list;
    private boolean returnAnIterator;

    //~ Constructors ===================================================================================================

    public MockMethodDefinitionSource(boolean includeInvalidAttributes, boolean returnAnIteratorWhenRequested) {
        returnAnIterator = returnAnIteratorWhenRequested;
        list = new Vector();

        ConfigAttributeDefinition def1 = new ConfigAttributeDefinition("MOCK_LOWER");
        list.add(def1);

        if (includeInvalidAttributes) {
            ConfigAttributeDefinition def2 = new ConfigAttributeDefinition(new String[] {"MOCK_LOWER","INVALID_ATTRIBUTE"});
            list.add(def2);
        }

        ConfigAttributeDefinition def3 = new ConfigAttributeDefinition(new String[] {"MOCK_UPPER", "RUN_AS_"});
        list.add(def3);

        if (includeInvalidAttributes) {
            ConfigAttributeDefinition def4 = new ConfigAttributeDefinition(new String[] {"MOCK_SOMETHING", "ANOTHER_INVALID"});
            list.add(def4);
        }
    }

    //~ Methods ========================================================================================================

    public Iterator getConfigAttributeDefinitions() {
        if (returnAnIterator) {
            return list.iterator();
        } else {
            return null;
        }
    }

    protected ConfigAttributeDefinition lookupAttributes(Method method) {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
