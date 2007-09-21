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
import java.util.List;

import org.springframework.security.ConfigAttribute;

/**
 * Configuration entry for {@link FilterInvocationDefinitionSource}, that holds
 * the url to be protected and the {@link ConfigAttribute}s as {@link String}
 * that apply to that url.
 *
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id$
 * @since 1.1
 */
public class FilterInvocationDefinitionSourceMapping {

    private String url;

    private List configAttributes = new ArrayList();

    /**
     * Url to be secured.
     *
     * @param url
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Url to be secured.
     *
     * @return the url
     */
    public String getUrl() {
        return url;
    }

    /**
     *
     * @param roles {@link List}&lt;{@link String}>
     */
    public void setConfigAttributes(List roles) {
        this.configAttributes = roles;
    }

    /**
     *
     * @return {@link List}&lt;{@link String}>
     */
    public List getConfigAttributes() {
        return configAttributes;
    }

    /**
     * Add a {@link ConfigAttribute} as {@link String}
     *
     * @param configAttribute
     */
    public void addConfigAttribute(String configAttribute) {
        configAttributes.add(configAttribute);
    }

}
