package org.springframework.security.web.authentication.preauth.websphere;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.rmi.PortableRemoteObject;
import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * WebSphere Security helper class to allow retrieval of the current username and groups.
 * <p>
 * See Spring Security Jira SEC-477.
 *
 * @author Ruud Senden
 * @author Stephane Manciot
 * @since 2.0
 */
final class DefaultWASUsernameAndGroupsExtractor implements WASUsernameAndGroupsExtractor {
    private static final Log logger = LogFactory.getLog(DefaultWASUsernameAndGroupsExtractor.class);

    private static final String USER_REGISTRY = "UserRegistry";

    private static Method getRunAsSubject = null;

    private static Method getGroupsForUser = null;

    private static Method getSecurityName = null;

    // SEC-803
    private static Class<?> wsCredentialClass = null;

    public final List<String> getGroupsForCurrentUser() {
        return getWebSphereGroups(getRunAsSubject());
    }

    public final String getCurrentUserName() {
        return getSecurityName(getRunAsSubject());
    }

    /**
     * Get the security name for the given subject.
     *
     * @param subject
     *            The subject for which to retrieve the security name
     * @return String the security name for the given subject
     */
    private static String getSecurityName(final Subject subject) {
        if (logger.isDebugEnabled()) {
            logger.debug("Determining Websphere security name for subject " + subject);
        }
        String userSecurityName = null;
        if (subject != null) {
            // SEC-803
            Object credential = subject.getPublicCredentials(getWSCredentialClass()).iterator().next();
            if (credential != null) {
                userSecurityName = (String)invokeMethod(getSecurityNameMethod(),credential,null);
            }
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Websphere security name is " + userSecurityName + " for subject " + subject);
        }
        return userSecurityName;
    }

    /**
     * Get the current RunAs subject.
     *
     * @return Subject the current RunAs subject
     */
    private static Subject getRunAsSubject() {
        logger.debug("Retrieving WebSphere RunAs subject");
        // get Subject: WSSubject.getCallerSubject ();
        return (Subject) invokeMethod(getRunAsSubjectMethod(), null, new Object[] {});
    }

    /**
     * Get the WebSphere group names for the given subject.
     *
     * @param subject
     *            The subject for which to retrieve the WebSphere group names
     * @return the WebSphere group names for the given subject
     */
    private static List<String> getWebSphereGroups(final Subject subject) {
        return getWebSphereGroups(getSecurityName(subject));
    }

    /**
     * Get the WebSphere group names for the given security name.
     *
     * @param securityName
     *            The security name for which to retrieve the WebSphere group names
     * @return the WebSphere group names for the given security name
     */
    @SuppressWarnings("unchecked")
    private static List<String> getWebSphereGroups(final String securityName) {
        Context ic = null;
        try {
            // TODO: Cache UserRegistry object
            ic = new InitialContext();
            Object objRef = ic.lookup(USER_REGISTRY);
            Object userReg = PortableRemoteObject.narrow(objRef, Class.forName ("com.ibm.websphere.security.UserRegistry"));
            if (logger.isDebugEnabled()) {
                logger.debug("Determining WebSphere groups for user " + securityName + " using WebSphere UserRegistry " + userReg);
            }
            final Collection groups = (Collection) invokeMethod(getGroupsForUserMethod(), userReg, new Object[]{ securityName });
            if (logger.isDebugEnabled()) {
                logger.debug("Groups for user " + securityName + ": " + groups.toString());
            }

            return new ArrayList(groups);
        } catch (Exception e) {
            logger.error("Exception occured while looking up groups for user", e);
            throw new RuntimeException("Exception occured while looking up groups for user", e);
        } finally {
            try {
                if (ic != null) {
                    ic.close();
                }
            } catch (NamingException e) {
                logger.debug("Exception occured while closing context", e);
            }
        }
    }

    private static Object invokeMethod(Method method, Object instance, Object[] args)
    {
        try {
            return method.invoke(instance,args);
        } catch (IllegalArgumentException e) {
            logger.error("Error while invoking method "+method.getClass().getName()+"."+method.getName()+"("+ Arrays.asList(args)+")",e);
            throw new RuntimeException("Error while invoking method "+method.getClass().getName()+"."+method.getName()+"("+Arrays.asList(args)+")",e);
        } catch (IllegalAccessException e) {
            logger.error("Error while invoking method "+method.getClass().getName()+"."+method.getName()+"("+Arrays.asList(args)+")",e);
            throw new RuntimeException("Error while invoking method "+method.getClass().getName()+"."+method.getName()+"("+Arrays.asList(args)+")",e);
        } catch (InvocationTargetException e) {
            logger.error("Error while invoking method "+method.getClass().getName()+"."+method.getName()+"("+Arrays.asList(args)+")",e);
            throw new RuntimeException("Error while invoking method "+method.getClass().getName()+"."+method.getName()+"("+Arrays.asList(args)+")",e);
        }
    }

    private static Method getMethod(String className, String methodName, String[] parameterTypeNames) {
        try {
            Class<?> c = Class.forName(className);
            final int len = parameterTypeNames.length;
            Class<?>[] parameterTypes = new Class[len];
            for (int i = 0; i < len; i++) {
                parameterTypes[i] = Class.forName(parameterTypeNames[i]);
            }
            return c.getDeclaredMethod(methodName, parameterTypes);
        } catch (ClassNotFoundException e) {
            logger.error("Required class"+className+" not found");
            throw new RuntimeException("Required class"+className+" not found",e);
        } catch (NoSuchMethodException e) {
            logger.error("Required method "+methodName+" with parameter types ("+ Arrays.asList(parameterTypeNames) +") not found on class "+className);
            throw new RuntimeException("Required class"+className+" not found",e);
        }
    }

    private static Method getRunAsSubjectMethod() {
        if (getRunAsSubject == null) {
            getRunAsSubject = getMethod("com.ibm.websphere.security.auth.WSSubject", "getRunAsSubject", new String[] {});
        }
        return getRunAsSubject;
    }

    private static Method getGroupsForUserMethod() {
        if (getGroupsForUser == null) {
            getGroupsForUser = getMethod("com.ibm.websphere.security.UserRegistry", "getGroupsForUser", new String[] { "java.lang.String" });
        }
        return getGroupsForUser;
    }

    private static Method getSecurityNameMethod() {
        if (getSecurityName == null) {
            getSecurityName = getMethod("com.ibm.websphere.security.cred.WSCredential", "getSecurityName", new String[] {});
        }
        return getSecurityName;
    }

    // SEC-803
    private static Class<?> getWSCredentialClass() {
        if (wsCredentialClass == null) {
            wsCredentialClass = getClass("com.ibm.websphere.security.cred.WSCredential");
        }
        return wsCredentialClass;
    }

    private static Class<?> getClass(String className) {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            logger.error("Required class " + className + " not found");
            throw new RuntimeException("Required class " + className + " not found",e);
        }
    }

}
