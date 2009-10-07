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

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractFallbackMethodSecurityMetadataSource;


/**
 * Sources method security metadata from major JSR 250 security annotations.
 *
 * @author Ben Alex
 * @version $Id$
 * @since 2.0
 */
public class Jsr250MethodSecurityMetadataSource extends AbstractFallbackMethodSecurityMetadataSource {

    protected Collection<ConfigAttribute> findAttributes(Class<?> clazz) {
        return processAnnotations(clazz.getAnnotations());
    }

    protected Collection<ConfigAttribute> findAttributes(Method method, Class<?> targetClass) {
        return processAnnotations(AnnotationUtils.getAnnotations(method));
    }

    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    private List<ConfigAttribute> processAnnotations(Annotation[] annotations) {
        if (annotations == null || annotations.length == 0) {
            return null;
        }
        List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>();

        for (Annotation a: annotations) {
            if (a instanceof DenyAll) {
                attributes.add(Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE);
                return attributes;
            }
            if (a instanceof PermitAll) {
                attributes.add(Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE);
                return attributes;
            }
            if (a instanceof RolesAllowed) {
                RolesAllowed ra = (RolesAllowed) a;

                for (String allowed : ra.value()) {
                    attributes.add(new Jsr250SecurityConfig(allowed));
                }
                return attributes;
            }
        }
        return null;
    }
}
