/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.metadata.Attributes;

import java.lang.reflect.Method;

import java.util.Collection;
import java.util.Iterator;


/**
 * Stores a {@link ConfigAttributeDefinition} for each method signature defined
 * by Commons Attributes.
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionAttributes implements MethodDefinitionSource {
    //~ Instance fields ========================================================

    private Attributes attributes;

    //~ Methods ================================================================

    public void setAttributes(Attributes attributes) {
        this.attributes = attributes;
    }

    public ConfigAttributeDefinition getAttributes(MethodInvocation invocation) {
        ConfigAttributeDefinition definition = new ConfigAttributeDefinition();

        Class interceptedClass = invocation.getMethod().getDeclaringClass();

        // add the class level attributes for the implementing class
        addClassAttributes(definition, interceptedClass);

        // add the class level attributes for the implemented interfaces
        addClassAttributes(definition, interceptedClass.getInterfaces());

        // add the method level attributes for the implemented method
        addMethodAttributes(definition, invocation.getMethod());

        // add the method level attributes for the implemented intreface methods
        addInterfaceMethodAttributes(definition, invocation.getMethod());

        return definition;
    }

    public Iterator getConfigAttributeDefinitions() {
        return null;
    }

    private void add(ConfigAttributeDefinition definition, Collection attribs) {
        for (Iterator iter = attribs.iterator(); iter.hasNext();) {
            Object o = (Object) iter.next();

            if (o instanceof ConfigAttribute) {
                definition.addConfigAttribute((ConfigAttribute) o);
            }
        }
    }

    private void addClassAttributes(ConfigAttributeDefinition definition,
        Class clazz) {
        addClassAttributes(definition, new Class[] {clazz});
    }

    private void addClassAttributes(ConfigAttributeDefinition definition,
        Class[] clazz) {
        for (int i = 0; i < clazz.length; i++) {
            Collection classAttributes = attributes.getAttributes(clazz[i]);

            if (classAttributes != null) {
                add(definition, classAttributes);
            }
        }
    }

    private void addInterfaceMethodAttributes(
        ConfigAttributeDefinition definition, Method method) {
        Class[] interfaces = method.getDeclaringClass().getInterfaces();

        for (int i = 0; i < interfaces.length; i++) {
            Class clazz = interfaces[i];

            try {
                Method m = clazz.getDeclaredMethod(method.getName(),
                        method.getParameterTypes());
                addMethodAttributes(definition, m);
            } catch (Exception e) {
                // this won't happen since we are getting a method from an interface that 
                // the declaring class implements
            }
        }
    }

    private void addMethodAttributes(ConfigAttributeDefinition definition,
        Method method) {
        // add the method level attributes
        Collection methodAttributes = attributes.getAttributes(method);

        if (methodAttributes != null) {
            add(definition, methodAttributes);
        }
    }
}
