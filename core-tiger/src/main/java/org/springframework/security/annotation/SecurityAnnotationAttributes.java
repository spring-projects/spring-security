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
package org.springframework.security.annotation;

import org.springframework.security.SecurityConfig;

import org.springframework.metadata.Attributes;

import org.springframework.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;


/**
 * Java 5 Annotation <code>Attributes</code> metadata implementation used for  secure method interception.<p>This
 * <code>Attributes</code> implementation will return security  configuration for classes described using the
 * <code>Secured</code> Java 5 annotation.</p>
 *  <p>The <code>SecurityAnnotationAttributes</code> implementation can be used to configure a
 * <code>MethodDefinitionAttributes</code> and  <code>MethodSecurityInterceptor</code> bean definition (see below).</p>
 *  <p>For example:<pre>&lt;bean id="attributes"
 *     class="org.springframework.security.annotation.SecurityAnnotationAttributes"/>&lt;bean id="objectDefinitionSource"
 *     class="org.springframework.security.intercept.method.MethodDefinitionAttributes">    &lt;property name="attributes">
 *         &lt;ref local="attributes"/>    &lt;/property>&lt;/bean>&lt;bean id="securityInterceptor"
 *     class="org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor">     . . .
 *      &lt;property name="objectDefinitionSource">         &lt;ref local="objectDefinitionSource"/>     &lt;/property>
 * &lt;/bean></pre></p>
 *  <p>These security annotations are similiar to the Commons Attributes approach, however they are using Java 5
 * language-level metadata support.</p>
 *  <p>This class should be used with Spring 2.0 or above, as it relies upon utility classes in Spring 2.0 for
 * correct introspection of annotations on bridge methods.</p>
 *
 * @author Mark St.Godard
 * @version $Id$
 *
 * @see org.springframework.security.annotation.Secured
 */
public class SecurityAnnotationAttributes implements Attributes {
    //~ Methods ========================================================================================================

    /**
     * Get the <code>Secured</code> attributes for a given target class.
     *
     * @param target The target method
     *
     * @return Collection of <code>SecurityConfig</code>
     *
     * @see Attributes#getAttributes
     */
    public Collection getAttributes(Class target) {
        Set<SecurityConfig> attributes = new HashSet<SecurityConfig>();

        for (Annotation annotation : target.getAnnotations()) {
            // check for Secured annotations
            if (annotation instanceof Secured) {
                Secured attr = (Secured) annotation;

                for (String auth : attr.value()) {
                    attributes.add(new SecurityConfig(auth));
                }

                break;
            }
        }

        return attributes;
    }

    public Collection getAttributes(Class clazz, Class filter) {
        throw new UnsupportedOperationException("Unsupported operation");
    }

    /**
     * Get the <code>Secured</code> attributes for a given target method.
     *
     * @param method The target method
     *
     * @return Collection of <code>SecurityConfig</code>
     *
     * @see Attributes#getAttributes
     */
    public Collection getAttributes(Method method) {
        Set<SecurityConfig> attributes = new HashSet<SecurityConfig>();

        Annotation[] annotations = null;

        // Use AnnotationUtils if in classpath (ie Spring 1.2.9+ deployment)
        try {
            Class clazz = ClassUtils.forName("org.springframework.core.annotation.AnnotationUtils");
            Method m = clazz.getMethod("getAnnotations", new Class[] {Method.class});
            annotations = (Annotation[]) m.invoke(null, new Object[] {method});
        } catch (Exception ex) {
            // Fallback to manual retrieval if no AnnotationUtils available
            annotations = method.getAnnotations();
        }

        for (Annotation annotation : annotations) {
            // check for Secured annotations
            if (annotation instanceof Secured) {
                Secured attr = (Secured) annotation;

                for (String auth : attr.value()) {
                    attributes.add(new SecurityConfig(auth));
                }

                break;
            }
        }

        return attributes;
    }

    public Collection getAttributes(Method method, Class clazz) {
        throw new UnsupportedOperationException("Unsupported operation");
    }

    public Collection getAttributes(Field field) {
        throw new UnsupportedOperationException("Unsupported operation");
    }

    public Collection getAttributes(Field field, Class clazz) {
        throw new UnsupportedOperationException("Unsupported operation");
    }
}
