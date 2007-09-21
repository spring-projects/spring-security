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

import java.util.Iterator;
import java.util.List;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;

/**
 * <p>
 * Decorator of {@link FilterInvocationDefinition} for easier configuration,
 * using {@link FilterInvocationDefinitionSourceMapping}.
 * </p>
 *
 * <p>
 * Delegates all calls to decorated object set in constructor
 * {@link #FilterInvocationDefinitionDecorator(FilterInvocationDefinition)} or
 * by calling {@link #setDecorated(FilterInvocationDefinition)}
 * </p>
 *
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id$
 * @since 1.1
 */
public class FilterInvocationDefinitionDecorator implements FilterInvocationDefinition {

    private FilterInvocationDefinition decorated;

    private List mappings;

    public FilterInvocationDefinitionDecorator() {
    }

    public FilterInvocationDefinitionDecorator(FilterInvocationDefinition decorated) {
        this.setDecorated(decorated);
    }

    /**
     * Set the decorated object
     *
     * @param decorated
     *            the decorated {@link FilterInvocationDefinition}
     */
    public void setDecorated(FilterInvocationDefinition decorated) {
        this.decorated = decorated;
    }

    /**
     * Get decorated object
     *
     * @return the decorated {@link FilterInvocationDefinition}
     */
    public FilterInvocationDefinition getDecorated() {
        return decorated;
    }

    /**
     * Configures the decorated {@link FilterInvocationDefinitionMap} easier,
     * using {@link FilterInvocationDefinitionSourceMapping}.
     *
     * @param mappings
     *            {@link List} of
     *            {@link FilterInvocationDefinitionSourceMapping} objects.
     */
    public void setMappings(List mappings) {

        if (decorated == null) {
            throw new IllegalStateException("decorated object has not been set");
        }

        this.mappings = mappings;
        Iterator it = mappings.iterator();
        while (it.hasNext()) {
            FilterInvocationDefinitionSourceMapping mapping = (FilterInvocationDefinitionSourceMapping) it.next();
            ConfigAttributeDefinition configDefinition = new ConfigAttributeDefinition();

            Iterator configAttributesIt = mapping.getConfigAttributes().iterator();
            while (configAttributesIt.hasNext()) {
                String s = (String) configAttributesIt.next();
                configDefinition.addConfigAttribute(new SecurityConfig(s));
            }

            decorated.addSecureUrl(mapping.getUrl(), configDefinition);
        }
    }

    /**
     * Get the mappings used for configuration.
     *
     * @return {@link List} of {@link FilterInvocationDefinitionSourceMapping}
     *         objects.
     */
    public List getMappings() {
        return mappings;
    }

    /**
     * Delegate to decorated object
     */
    public void addSecureUrl(String expression, ConfigAttributeDefinition attr) {
        getDecorated().addSecureUrl(expression, attr);
    }

    /**
     * Delegate to decorated object
     */
    public boolean isConvertUrlToLowercaseBeforeComparison() {
        return getDecorated().isConvertUrlToLowercaseBeforeComparison();
    }

    /**
     * Delegate to decorated object
     */
    public void setConvertUrlToLowercaseBeforeComparison(boolean convertUrlToLowercaseBeforeComparison) {
        getDecorated().setConvertUrlToLowercaseBeforeComparison(convertUrlToLowercaseBeforeComparison);
    }

    /**
     * Delegate to decorated object
     */
    public ConfigAttributeDefinition getAttributes(Object object) throws IllegalArgumentException {
        return getDecorated().getAttributes(object);
    }

    /**
     * Delegate to decorated object
     */
    public Iterator getConfigAttributeDefinitions() {
        return getDecorated().getConfigAttributeDefinitions();
    }

    /**
     * Delegate to decorated object
     */
    public boolean supports(Class clazz) {
        return getDecorated().supports(clazz);
    }
}
