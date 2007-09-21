/* Copyright 2006 Acegi Technology Pty Limited
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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;

import junit.framework.TestCase;

/**
 * Test for {@link FilterInvocationDefinitionDecorator}
 *
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id$
 */
public class FilterInvocationDefinitionDecoratorTest extends TestCase {

    private FilterInvocationDefinitionDecorator decorator;

    private FilterInvocationDefinition decorated;

    protected void setUp() throws Exception {
        super.setUp();
        decorated = new MockFilterInvocationDefinition();
        decorator = new FilterInvocationDefinitionDecorator(decorated);
    }

    public void testFilterInvocationDefinitionMapDecorator() {
        decorator = new FilterInvocationDefinitionDecorator();
        decorator.setDecorated(decorated);
        assertEquals(decorated, decorator.getDecorated());
    }

    public void testSetMappings() {
        List roles = new ArrayList();
        roles.add("ROLE_USER");
        roles.add("ROLE_ADMIN");

        FilterInvocationDefinitionSourceMapping mapping = new FilterInvocationDefinitionSourceMapping();
        mapping.setUrl("/secure/**");
        mapping.setConfigAttributes(roles);

        List mappings = new ArrayList();
        mappings.add(mapping);

        decorator.setMappings(mappings);

        ConfigAttributeDefinition configDefinition = new ConfigAttributeDefinition();
        Iterator it = roles.iterator();
        while (it.hasNext()) {
            String role = (String) it.next();
            configDefinition.addConfigAttribute(new SecurityConfig(role));
        }

        it = decorator.getConfigAttributeDefinitions();
        int i = 0;
        while (it.hasNext()) {
            i++;
            assertEquals(configDefinition, it.next());
        }
        assertEquals(1, i);

        assertEquals(mappings, decorator.getMappings());
    }
}
