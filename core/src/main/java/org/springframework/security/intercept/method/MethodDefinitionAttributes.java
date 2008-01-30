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

package org.springframework.security.intercept.method;

import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;

import org.springframework.metadata.Attributes;

import java.lang.reflect.Method;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;


/**
 * Provides {@link ConfigAttributeDefinition}s for a method signature (via the <tt>lookupAttributes</tt> method)
 * by delegating to a configured {@link Attributes} object. The latter may use Java 5 annotations, Commons attributes
 * or some other approach to determine the <tt>ConfigAttribute</tt>s which apply. 
 * <p>
 * This class will only detect those attributes which are defined for:
 *  <ul>
 *      <li>The class-wide attributes defined for the intercepted class.</li>
 *      <li>The class-wide attributes defined for interfaces explicitly implemented by the intercepted class.</li>
 *      <li>The method-specific attributes defined for the intercepted method of the intercepted class.</li>
 *      <li>The method-specific attributes defined by any explicitly implemented interface if that interface
 *      contains a method signature matching that of the intercepted method.</li>
 *  </ul>
 * <p>
 * Note that attributes defined against parent classes (either for their methods or interfaces) are not
 * detected. The attributes must be defined against an explicit method or interface on the intercepted class.
 * <p>
 * Attributes detected that do not implement {@link ConfigAttribute} will be ignored.
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionAttributes extends AbstractMethodDefinitionSource {
    //~ Instance fields ================================================================================================

    private Attributes attributes;

    //~ Methods ========================================================================================================

    private void add(List definition, Collection attribs) {
        for (Iterator iter = attribs.iterator(); iter.hasNext();) {
            Object o = iter.next();

            if (o instanceof ConfigAttribute) {
                definition.add(o);
            }
        }
    }

    private void addClassAttributes(List definition, Class[] clazz) {
        for (int i = 0; i < clazz.length; i++) {
            Collection classAttributes = attributes.getAttributes(clazz[i]);

            if (classAttributes != null) {
                add(definition, classAttributes);
            }
        }
    }

    private void addInterfaceMethodAttributes(List definition, Method method) {
        Class[] interfaces = method.getDeclaringClass().getInterfaces();

        for (int i = 0; i < interfaces.length; i++) {
            Class clazz = interfaces[i];

            try {
                Method m = clazz.getDeclaredMethod(method.getName(), (Class[]) method.getParameterTypes());
                addMethodAttributes(definition, m);
            } catch (Exception e) {
                // this won't happen since we are getting a method from an interface that
                // the declaring class implements
            }
        }
    }

    private void addMethodAttributes(List definition, Method method) {
        // add the method level attributes
        Collection methodAttributes = attributes.getAttributes(method);

        if (methodAttributes != null) {
            add(definition, methodAttributes);
        }
    }

    public Iterator getConfigAttributeDefinitions() {
        return null;
    }

    protected ConfigAttributeDefinition lookupAttributes(Method method) {
        Class interceptedClass = method.getDeclaringClass();
        List attributes = new ArrayList();

        // add the class level attributes for the implementing class
        addClassAttributes(attributes, new Class[] {interceptedClass});

        // add the class level attributes for the implemented interfaces
        addClassAttributes(attributes, interceptedClass.getInterfaces());

        // add the method level attributes for the implemented method
        addMethodAttributes(attributes, method);

        // add the method level attributes for the implemented intreface methods
        addInterfaceMethodAttributes(attributes, method);

        if (attributes.size() == 0) {
            return null;
        }

        return new ConfigAttributeDefinition(attributes);
    }

    public void setAttributes(Attributes attributes) {
        this.attributes = attributes;
    }
}
