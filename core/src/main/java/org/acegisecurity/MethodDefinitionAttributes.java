/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
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

    private void addInterfaceMethodAttributes(ConfigAttributeDefinition definition,
                                              Method method) {
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
