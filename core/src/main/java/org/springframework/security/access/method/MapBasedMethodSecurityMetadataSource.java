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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;


/**
 * Stores a list of <tt>ConfigAttribute</tt>s for a method or class signature.
 *
 * <p>
 * This class is the preferred implementation of {@link MethodSecurityMetadataSource} for XML-based
 * definition of method security metadata. To assist in XML-based definition, wildcard support
 * is provided.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 * @since 2.0
 */
public class MapBasedMethodSecurityMetadataSource extends AbstractFallbackMethodSecurityMetadataSource implements BeanClassLoaderAware {

    //~ Instance fields ================================================================================================
    private ClassLoader beanClassLoader = ClassUtils.getDefaultClassLoader();

    /** Map from RegisteredMethod to ConfigAttribute list */
    protected Map<RegisteredMethod, List<ConfigAttribute>> methodMap = new HashMap<RegisteredMethod, List<ConfigAttribute>>();

    /** Map from RegisteredMethod to name pattern used for registration */
    private Map<RegisteredMethod, String> nameMap = new HashMap<RegisteredMethod, String>();

    //~ Methods ========================================================================================================

    public MapBasedMethodSecurityMetadataSource() {
    }

    /**
     * Creates the <tt>MapBasedMethodSecurityMetadataSource</tt> from a
     * @param methodMap map of method names to <tt>ConfigAttribute</tt>s.
     */
    public MapBasedMethodSecurityMetadataSource(Map<String, List<ConfigAttribute>> methodMap) {
        for (Map.Entry<String, List<ConfigAttribute>> entry : methodMap.entrySet()) {
            addSecureMethod(entry.getKey(), entry.getValue());
        }
    }

    /**
     * Implementation does not support class-level attributes.
     */
    protected List<ConfigAttribute> findAttributes(Class<?> clazz) {
        return null;
    }

    /**
     * Will walk the method inheritance tree to find the most specific declaration applicable.
     */
    protected List<ConfigAttribute> findAttributes(Method method, Class<?> targetClass) {
        if (targetClass == null) {
            return null;
        }

        return findAttributesSpecifiedAgainst(method, targetClass);
    }

    private List<ConfigAttribute> findAttributesSpecifiedAgainst(Method method, Class<?> clazz) {
        RegisteredMethod registeredMethod = new RegisteredMethod(method, clazz);
        if (methodMap.containsKey(registeredMethod)) {
            return (List<ConfigAttribute>) methodMap.get(registeredMethod);
        }
        // Search superclass
        if (clazz.getSuperclass() != null) {
            return findAttributesSpecifiedAgainst(method, clazz.getSuperclass());
        }
        return null;
    }

    /**
     * Add configuration attributes for a secure method. Method names can end or start with <code>&#42</code>
     * for matching multiple methods.
     *
     * @param name type and method name, separated by a dot
     * @param attr required authorities associated with the method
     */
    private void addSecureMethod(String name, List<ConfigAttribute> attr) {
        int lastDotIndex = name.lastIndexOf(".");

        if (lastDotIndex == -1) {
            throw new IllegalArgumentException("'" + name + "' is not a valid method name: format is FQN.methodName");
        }

        String methodName = name.substring(lastDotIndex + 1);
        Assert.hasText(methodName, "Method not found for '" + name + "'");

        String typeName = name.substring(0, lastDotIndex);
        Class<?> type = ClassUtils.resolveClassName(typeName, this.beanClassLoader);

        addSecureMethod(type, methodName, attr);
    }

    /**
     * Add configuration attributes for a secure method. Mapped method names can end or start with <code>&#42</code>
     * for matching multiple methods.
     *
     * @param javaType target interface or class the security configuration attribute applies to
     * @param mappedName mapped method name, which the javaType has declared or inherited
     * @param attr required authorities associated with the method
     */
    public void addSecureMethod(Class<?> javaType, String mappedName, List<ConfigAttribute> attr) {
        String name = javaType.getName() + '.' + mappedName;

        if (logger.isDebugEnabled()) {
            logger.debug("Request to add secure method [" + name + "] with attributes [" + attr + "]");
        }

        Method[] methods = javaType.getMethods();
        List<Method> matchingMethods = new ArrayList<Method>();

        for (int i = 0; i < methods.length; i++) {
            if (methods[i].getName().equals(mappedName) || isMatch(methods[i].getName(), mappedName)) {
                matchingMethods.add(methods[i]);
            }
        }

        if (matchingMethods.isEmpty()) {
            throw new IllegalArgumentException("Couldn't find method '" + mappedName + "' on '" + javaType + "'");
        }

        // register all matching methods
        for (Method method : matchingMethods) {
            RegisteredMethod registeredMethod = new RegisteredMethod(method, javaType);
            String regMethodName = (String) this.nameMap.get(registeredMethod);

            if ((regMethodName == null) || (!regMethodName.equals(name) && (regMethodName.length() <= name.length()))) {
                // no already registered method name, or more specific
                // method name specification now -> (re-)register method
                if (regMethodName != null) {
                    logger.debug("Replacing attributes for secure method [" + method + "]: current name [" + name
                        + "] is more specific than [" + regMethodName + "]");
                }

                this.nameMap.put(registeredMethod, name);
                addSecureMethod(registeredMethod, attr);
            } else {
                logger.debug("Keeping attributes for secure method [" + method + "]: current name [" + name
                    + "] is not more specific than [" + regMethodName + "]");
            }
        }
    }

    /**
     * Adds configuration attributes for a specific method, for example where the method has been
     * matched using a pointcut expression. If a match already exists in the map for the method, then
     * the existing match will be retained, so that if this method is called for a more general pointcut
     * it will not override a more specific one which has already been added. This
     */
    public void addSecureMethod(Class<?> javaType, Method method, List<ConfigAttribute> attr) {
        RegisteredMethod key = new RegisteredMethod(method, javaType);

        if (methodMap.containsKey(key)) {
            logger.debug("Method [" + method + "] is already registered with attributes [" + methodMap.get(key) + "]");
            return;
        }

        methodMap.put(key, attr);
    }

    /**
     * Add configuration attributes for a secure method.
     *
     * @param method the method to be secured
     * @param attr required authorities associated with the method
     */
    private void addSecureMethod(RegisteredMethod method, List<ConfigAttribute> attr) {
        Assert.notNull(method, "RegisteredMethod required");
        Assert.notNull(attr, "Configuration attribute required");
        if (logger.isInfoEnabled()) {
            logger.info("Adding secure method [" + method + "] with attributes [" + attr + "]");
        }
        this.methodMap.put(method, attr);
    }

    /**
     * Obtains the configuration attributes explicitly defined against this bean.
     *
     * @return the attributes explicitly defined against this bean
     */
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<ConfigAttribute>();

        for (List<ConfigAttribute> attributeList : methodMap.values()) {
            allAttributes.addAll(attributeList);
        }

        return allAttributes;
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

    public void setBeanClassLoader(ClassLoader beanClassLoader) {
        Assert.notNull(beanClassLoader, "Bean class loader required");
        this.beanClassLoader = beanClassLoader;
    }

    /**
     * @return map size (for unit tests and diagnostics)
     */
    public int getMethodMapSize() {
        return methodMap.size();
    }

    /**
     * Stores both the Java Method as well as the Class we obtained the Method from. This is necessary because Method only
     * provides us access to the declaring class. It doesn't provide a way for us to introspect which Class the Method
     * was registered against. If a given Class inherits and redeclares a method (i.e. calls super();) the registered Class
     * and declaring Class are the same. If a given class merely inherits but does not redeclare a method, the registered
     * Class will be the Class we're invoking against and the Method will provide details of the declared class.
     */
    private class RegisteredMethod {
        private Method method;
        private Class<?> registeredJavaType;

        public RegisteredMethod(Method method, Class<?> registeredJavaType) {
            Assert.notNull(method, "Method required");
            Assert.notNull(registeredJavaType, "Registered Java Type required");
            this.method = method;
            this.registeredJavaType = registeredJavaType;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj != null && obj instanceof RegisteredMethod) {
                RegisteredMethod rhs = (RegisteredMethod) obj;
                return method.equals(rhs.method) && registeredJavaType.equals(rhs.registeredJavaType);
            }
            return false;
        }

        public int hashCode() {
            return method.hashCode() * registeredJavaType.hashCode();
        }

        public String toString() {
            return "RegisteredMethod[" + registeredJavaType.getName() + "; " + method + "]";
        }
    }

}
