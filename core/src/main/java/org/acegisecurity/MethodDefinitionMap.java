/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.Method;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;


/**
 * Stores a {@link ConfigAttributeDefinition} for each method signature defined
 * in a bean context.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionMap implements MethodDefinitionSource {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(MethodDefinitionMap.class);

    //~ Instance fields ========================================================

    /** Map from Method to ApplicationDefinition */
    protected Map methodMap = new HashMap();

    /** Map from Method to name pattern used for registration */
    private Map nameMap = new HashMap();

    //~ Methods ================================================================

    public ConfigAttributeDefinition getAttributes(MethodInvocation invocation) {
        return (ConfigAttributeDefinition) this.methodMap.get(invocation
                                                              .getMethod());
    }

    public Iterator getConfigAttributeDefinitions() {
        return methodMap.values().iterator();
    }

    /**
     * Add required authorities for a secure method. Method names can end or
     * start with "" for matching multiple methods.
     *
     * @param method the method to be secured
     * @param attr required authorities associated with the method
     */
    public void addSecureMethod(Method method, ConfigAttributeDefinition attr) {
        logger.info("Adding secure method [" + method + "] with attributes ["
                    + attr + "]");
        this.methodMap.put(method, attr);
    }

    /**
     * Add required authorities for a secure method. Method names can end or
     * start with "" for matching multiple methods.
     *
     * @param name class and method name, separated by a dot
     * @param attr required authorities associated with the method
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public void addSecureMethod(String name, ConfigAttributeDefinition attr) {
        int lastDotIndex = name.lastIndexOf(".");

        if (lastDotIndex == -1) {
            throw new IllegalArgumentException("'" + name
                                               + "' is not a valid method name: format is FQN.methodName");
        }

        String className = name.substring(0, lastDotIndex);
        String methodName = name.substring(lastDotIndex + 1);

        try {
            Class clazz = Class.forName(className, true,
                                        Thread.currentThread()
                                              .getContextClassLoader());
            addSecureMethod(clazz, methodName, attr);
        } catch (ClassNotFoundException ex) {
            throw new IllegalArgumentException("Class '" + className
                                               + "' not found");
        }
    }

    /**
     * Add required authorities for a secure method. Method names can end or
     * start with "" for matching multiple methods.
     *
     * @param clazz target interface or class
     * @param mappedName mapped method name
     * @param attr required authorities associated with the method
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public void addSecureMethod(Class clazz, String mappedName,
                                ConfigAttributeDefinition attr) {
        String name = clazz.getName() + '.' + mappedName;

        if (logger.isDebugEnabled()) {
            logger.debug("Adding secure method [" + name
                         + "] with attributes [" + attr + "]");
        }

        Method[] methods = clazz.getDeclaredMethods();
        List matchingMethods = new ArrayList();

        for (int i = 0; i < methods.length; i++) {
            if (methods[i].getName().equals(mappedName)
                    || isMatch(methods[i].getName(), mappedName)) {
                matchingMethods.add(methods[i]);
            }
        }

        if (matchingMethods.isEmpty()) {
            throw new IllegalArgumentException("Couldn't find method '"
                                               + mappedName + "' on " + clazz);
        }

        // register all matching methods
        for (Iterator it = matchingMethods.iterator(); it.hasNext();) {
            Method method = (Method) it.next();
            String regMethodName = (String) this.nameMap.get(method);

            if ((regMethodName == null)
                    || (!regMethodName.equals(name)
                    && (regMethodName.length() <= name.length()))) {
                // no already registered method name, or more specific
                // method name specification now -> (re-)register method
                if (logger.isDebugEnabled() && (regMethodName != null)) {
                    logger.debug("Replacing attributes for secure method ["
                                 + method + "]: current name [" + name
                                 + "] is more specific than [" + regMethodName
                                 + "]");
                }

                this.nameMap.put(method, name);
                addSecureMethod(method, attr);
            } else {
                if (logger.isDebugEnabled() && (regMethodName != null)) {
                    logger.debug("Keeping attributes for secure method ["
                                 + method + "]: current name [" + name
                                 + "] is not more specific than ["
                                 + regMethodName + "]");
                }
            }
        }
    }

    /**
     * Return if the given method name matches the mapped name. The default
     * implementation checks for "xxx" and "xxx" matches.
     *
     * @param methodName the method name of the class
     * @param mappedName the name in the descriptor
     *
     * @return if the names match
     */
    private boolean isMatch(String methodName, String mappedName) {
        return (mappedName.endsWith("*")
               && methodName.startsWith(mappedName.substring(0,
                                                             mappedName.length()
                                                             - 1)))
               || (mappedName.startsWith("*")
               && methodName.endsWith(mappedName.substring(1,
                                                           mappedName.length())));
    }
}
