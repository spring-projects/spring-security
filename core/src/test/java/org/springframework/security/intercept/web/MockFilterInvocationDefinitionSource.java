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

package org.springframework.security.intercept.web;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;
import org.springframework.security.util.AntUrlPathMatcher;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;


/**
 * Mock for {@link FilterInvocationDefinitionSource}
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockFilterInvocationDefinitionSource extends AbstractFilterInvocationDefinitionSource {
    //~ Instance fields ================================================================================================

    private List list;
    private boolean returnAnIterator;

    //~ Constructors ===================================================================================================

    public MockFilterInvocationDefinitionSource(boolean includeInvalidAttributes, boolean returnAnIteratorWhenRequested) {
        super(new AntUrlPathMatcher()); // doesn't matter
        returnAnIterator = returnAnIteratorWhenRequested;
        list = new Vector();

        ConfigAttributeDefinition def1 = new ConfigAttributeDefinition();
        def1.addConfigAttribute(new SecurityConfig("MOCK_LOWER"));
        list.add(def1);

        if (includeInvalidAttributes) {
            ConfigAttributeDefinition def2 = new ConfigAttributeDefinition();
            def2.addConfigAttribute(new SecurityConfig("MOCK_LOWER"));
            def2.addConfigAttribute(new SecurityConfig("INVALID_ATTRIBUTE"));
            list.add(def2);
        }

        ConfigAttributeDefinition def3 = new ConfigAttributeDefinition();
        def3.addConfigAttribute(new SecurityConfig("MOCK_UPPER"));
        def3.addConfigAttribute(new SecurityConfig("RUN_AS"));
        list.add(def3);

        if (includeInvalidAttributes) {
            ConfigAttributeDefinition def4 = new ConfigAttributeDefinition();
            def4.addConfigAttribute(new SecurityConfig("MOCK_SOMETHING"));
            def4.addConfigAttribute(new SecurityConfig("ANOTHER_INVALID"));
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

    public ConfigAttributeDefinition lookupAttributes(String url) {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
