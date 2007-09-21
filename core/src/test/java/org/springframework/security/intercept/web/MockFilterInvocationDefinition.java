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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.springframework.security.ConfigAttributeDefinition;

/**
 * Mock for {@link FilterInvocationDefinitionMap}
 *
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id: MockFilterInvocationDefinitionSource.java 1496 2006-05-23
 *          13:38:33Z benalex $
 */
public class MockFilterInvocationDefinition implements FilterInvocationDefinition {

    private Map secureUrls = new HashMap();

    private boolean convertUrlToLowercaseBeforeComparison = false;

    public void addSecureUrl(String expression, ConfigAttributeDefinition attr) {
        secureUrls.put(expression, attr);
    }

    public boolean isConvertUrlToLowercaseBeforeComparison() {
        return convertUrlToLowercaseBeforeComparison;
    }

    public void setConvertUrlToLowercaseBeforeComparison(boolean convertUrlToLowercaseBeforeComparison) {
        this.convertUrlToLowercaseBeforeComparison = convertUrlToLowercaseBeforeComparison;
    }

    public ConfigAttributeDefinition getSecureUrl(String expression) {
        return (ConfigAttributeDefinition) secureUrls.get(expression);
    }

    public ConfigAttributeDefinition getAttributes(Object object) throws IllegalArgumentException {
        return (ConfigAttributeDefinition) secureUrls.get(object);
    }

    public Iterator getConfigAttributeDefinitions() {
        return secureUrls.values().iterator();
    }

    public boolean supports(Class clazz) {
        return true;
    }
}
