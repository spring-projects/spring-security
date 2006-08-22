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

package org.acegisecurity.intercept.method;

import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.SecurityConfig;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.Method;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;


/**
 * Stores a {@link ConfigAttributeDefinition} for each method signature defined in a bean context.<p>For
 * consistency with {@link MethodDefinitionAttributes} as well as support for
 * <code>MethodDefinitionSourceAdvisor</code>, this implementation will return a
 * <code>ConfigAttributeDefinition</code> containing all configuration attributes defined against:
 *  <ul>
 *      <li>The method-specific attributes defined for the intercepted method of the intercepted class.</li>
 *      <li>The method-specific attributes defined by any explicitly implemented interface if that interface
 *      contains a method signature matching that of the intercepted method.</li>
 *  </ul>
 *  </p>
 *  <p>In general you should therefore define the <b>interface method</b>s of your secure objects, not the
 * implementations. For example, define <code>com.company.Foo.findAll=ROLE_TEST</code> but not
 * <code>com.company.FooImpl.findAll=ROLE_TEST</code>.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionMap extends AbstractMethodDefinitionSource {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(MethodDefinitionMap.class);

    //~ Instance fields ================================================================================================

    /** Map from Method to ApplicationDefinition */
    protected Map methodMap = new HashMap();

    /** Map from Method to name pattern used for registration */
    private Map nameMap = new HashMap();

    //~ Methods ========================================================================================================

    /**
     * Add configuration attributes for a secure method. Method names can end or start with <code>&#42</code>
     * for matching multiple methods.
     *
     * @param method the method to be secured
     * @param attr required authorities associated with the method
     */
    public void addSecureMethod(Method method, ConfigAttributeDefinition attr) {
        logger.info("Adding secure method [" + method + "] with attributes [" + attr + "]");
        this.methodMap.put(method, attr);
    }

    /**
     * Add configuration attributes for a secure method. Method names can end or start with <code>&#42</code>
     * for matching multiple methods.
     *
     * @param name class and method name, separated by a dot
     * @param attr required authorities associated with the method
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public void addSecureMethod(String name, ConfigAttributeDefinition attr) {
        int lastDotIndex = name.lastIndexOf(".");

        if (lastDotIndex == -1) {
            throw new IllegalArgumentException("'" + name + "' is not a valid method name: format is FQN.methodName");
        }

        String className = name.substring(0, lastDotIndex);
        String methodName = name.substring(lastDotIndex + 1);

        try {
            Class clazz = Class.forName(className, true, Thread.currentThread().getContextClassLoader());
            addSecureMethod(clazz, methodName, attr);
        } catch (ClassNotFoundException ex) {
            throw new IllegalArgumentException("Class '" + className + "' not found");
        }
    }

    /**
     * Add configuration attributes for a secure method. Method names can end or start with <code>&#42</code>
     * for matching multiple methods.
     *
     * @param clazz target interface or class
     * @param mappedName mapped method name
     * @param attr required authorities associated with the method
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public void addSecureMethod(Class clazz, String mappedName, ConfigAttributeDefinition attr) {
        String name = clazz.getName() + '.' + mappedName;

        if (logger.isDebugEnabled()) {
            logger.debug("Adding secure method [" + name + "] with attributes [" + attr + "]");
        }

        Method[] methods = clazz.getDeclaredMethods();
        List matchingMethods = new ArrayList();

        for (int i = 0; i < methods.length; i++) {
            if (methods[i].getName().equals(mappedName) || isMatch(methods[i].getName(), mappedName)) {
                matchingMethods.add(methods[i]);
            }
        }

        if (matchingMethods.isEmpty()) {
            throw new IllegalArgumentException("Couldn't find method '" + mappedName + "' on " + clazz);
        }

        // register all matching methods
        for (Iterator it = matchingMethods.iterator(); it.hasNext();) {
            Method method = (Method) it.next();
            String regMethodName = (String) this.nameMap.get(method);

            if ((regMethodName == null) || (!regMethodName.equals(name) && (regMethodName.length() <= name.length()))) {
                // no already registered method name, or more specific
                // method name specification now -> (re-)register method
                if (regMethodName != null) {
                    logger.debug("Replacing attributes for secure method [" + method + "]: current name [" + name
                        + "] is more specific than [" + regMethodName + "]");
                }

                this.nameMap.put(method, name);
                addSecureMethod(method, attr);
            } else {
                logger.debug("Keeping attributes for secure method [" + method + "]: current name [" + name
                    + "] is not more specific than [" + regMethodName + "]");
            }
        }
    }

    /**
     * Obtains the configuration attributes explicitly defined against this bean. This method will not return
     * implicit configuration attributes that may be returned by {@link #lookupAttributes(Method)} as it does not have
     * access to a method invocation at this time.
     *
     * @return the attributes explicitly defined against this bean
     */
    public Iterator getConfigAttributeDefinitions() {
        return methodMap.values().iterator();
    }

    /**
     * Obtains the number of configuration attributes explicitly defined against this bean. This method will
     * not return implicit configuration attributes that may be returned by {@link #lookupAttributes(Method)} as it
     * does not have access to a method invocation at this time.
     *
     * @return the number of configuration attributes explicitly defined against this bean
     */
    public int getMethodMapSize() {
        return this.methodMap.size();
    }

    /**
     * Return if the given method name matches the mapped name. The default implementation checks for "xxx" and
     * "xxx" matches.
     *
     * @param methodName the method name of the class
     * @param mappedName the name in the descriptor
     *
     * @return if the names match
     */
    private boolean isMatch(String methodName, String mappedName) {
        return (mappedName.endsWith("*") && methodName.startsWith(mappedName.substring(0, mappedName.length() - 1)))
        || (mappedName.startsWith("*") && methodName.endsWith(mappedName.substring(1, mappedName.length())));
    }

    protected ConfigAttributeDefinition lookupAttributes(Method method) {
        ConfigAttributeDefinition definition = new ConfigAttributeDefinition();

        // Add attributes explictly defined for this method invocation
        ConfigAttributeDefinition directlyAssigned = (ConfigAttributeDefinition) this.methodMap.get(method);
        merge(definition, directlyAssigned);

        // Add attributes explicitly defined for this method invocation's interfaces
        Class[] interfaces = method.getDeclaringClass().getInterfaces();

        for (int i = 0; i < interfaces.length; i++) {
            Class clazz = interfaces[i];

            try {
                // Look for the method on the current interface
                Method interfaceMethod = clazz.getDeclaredMethod(method.getName(), (Class[]) method.getParameterTypes());
                ConfigAttributeDefinition interfaceAssigned = (ConfigAttributeDefinition) this.methodMap.get(interfaceMethod);
                merge(definition, interfaceAssigned);
            } catch (Exception e) {
                // skip this interface
            }
        }

        // Return null if empty, as per abstract superclass contract
        if (definition.size() == 0) {
            return null;
        } else {
            return definition;
        }
    }

    private void merge(ConfigAttributeDefinition definition, ConfigAttributeDefinition toMerge) {
        if (toMerge == null) {
            return;
        }

        Iterator attribs = toMerge.getConfigAttributes();

        while (attribs.hasNext()) {
            definition.addConfigAttribute((ConfigAttribute) attribs.next());
        }
    }

    /**
     * Easier configuration of the instance, using {@link MethodDefinitionSourceMapping}.
     * 
     * @param mappings {@link List} of {@link MethodDefinitionSourceMapping} objects.
     */
    public void setMappings(List mappings) {
        Iterator it = mappings.iterator();
        while (it.hasNext()) {
            MethodDefinitionSourceMapping mapping = (MethodDefinitionSourceMapping) it.next();
            ConfigAttributeDefinition configDefinition = new ConfigAttributeDefinition();

            Iterator configAttributesIt = mapping.getConfigAttributes().iterator();
            while (configAttributesIt.hasNext()) {
                String s = (String) configAttributesIt.next();
                configDefinition.addConfigAttribute(new SecurityConfig(s));
            }

            addSecureMethod(mapping.getMethodName(), configDefinition);
        }
    }
}
