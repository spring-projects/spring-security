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

package org.springframework.security.access.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.method.AbstractFallbackMethodSecurityMetadataSource;


/**
 * Sources method security metadata from Spring Security's {@link Secured} annotation.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecuredAnnotationSecurityMetadataSource extends AbstractFallbackMethodSecurityMetadataSource {

    protected List<ConfigAttribute> findAttributes(Class<?> clazz) {
        return processAnnotation(clazz.getAnnotation(Secured.class));
    }

    protected List<ConfigAttribute> findAttributes(Method method, Class<?> targetClass) {
        return processAnnotation(AnnotationUtils.findAnnotation(method, Secured.class));
    }

    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    private List<ConfigAttribute> processAnnotation(Annotation a) {
        if (a == null || !(a instanceof Secured)) {
            return null;
        }

        String[] attributeTokens = ((Secured) a).value();
        List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>(attributeTokens.length);

        for(String token : attributeTokens) {
            attributes.add(new SecurityConfig(token));
        }

        return attributes;
    }
}
