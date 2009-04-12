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

package org.springframework.security.access.intercept.method;

import java.beans.PropertyEditorSupport;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.springframework.beans.propertyeditors.PropertiesEditor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.util.StringUtils;


/**
 * Property editor to assist with the setup of a {@link MethodSecurityMetadataSource}.
 * <p>
 * The class creates and populates a {@link MapBasedMethodSecurityMetadataSource}.
 *
 * @author Ben Alex
 * @deprecated use method annotations or the protect-pointcut support from the namespace
 * @version $Id$
 */
public class MethodSecurityMetadataSourceEditor extends PropertyEditorSupport {
    //~ Methods ========================================================================================================

    @SuppressWarnings("unchecked")
    public void setAsText(String s) throws IllegalArgumentException {
        if ((s == null) || "".equals(s)) {
            setValue(new MapBasedMethodSecurityMetadataSource());
            return;
        }

        // Use properties editor to tokenize the string
        PropertiesEditor propertiesEditor = new PropertiesEditor();
        propertiesEditor.setAsText(s);

        Properties props = (Properties) propertiesEditor.getValue();

        // Now we have properties, process each one individually
        Map<String, List<ConfigAttribute>> mappings = new LinkedHashMap<String, List<ConfigAttribute>>();

        for (Iterator iter = props.keySet().iterator(); iter.hasNext();) {
            String name = (String) iter.next();
            String value = props.getProperty(name);

            String[] tokens = StringUtils.commaDelimitedListToStringArray(value);
            List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>(tokens.length);

            for(String token : tokens) {
                attributes.add(new SecurityConfig(token));
            }

            mappings.put(name, attributes);
        }

        setValue(new MapBasedMethodSecurityMetadataSource(mappings));
    }
}
