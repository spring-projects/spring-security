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

package org.springframework.security.intercept.method;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.ConfigAttribute;

/**
 * Configuration entry for {@link MethodDefinitionSource}, that holds
 * the method to be protected and the {@link ConfigAttribute}s as {@link String}
 * that apply to that url.
 *
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id$
 * @since 1.1
 */
public class MethodDefinitionSourceMapping {

    private String methodName;

    private List configAttributes = new ArrayList();

    /**
     * Name of the method to be secured, including package and class name.
     * eg. <code>org.mydomain.MyClass.myMethod</code>
     *
     * @param methodName
     */
    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    /**
     * Name of the method to be secured.
     *
     * @return the name of the method
     */
    public String getMethodName() {
        return methodName;
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
