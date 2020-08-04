/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;

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

	private static final String PORTABLE_REMOTE_OBJECT_CLASSNAME = "javax.rmi.PortableRemoteObject";

	private static final String USER_REGISTRY = "UserRegistry";

	private static Method getRunAsSubject = null;

	private static Method getGroupsForUser = null;

	private static Method getSecurityName = null;

	private static Method narrow = null;

	// SEC-803
	private static Class<?> wsCredentialClass = null;

	@Override
	public List<String> getGroupsForCurrentUser() {
		return getWebSphereGroups(getRunAsSubject());
	}

	@Override
	public String getCurrentUserName() {
		return getSecurityName(getRunAsSubject());
	}

	/**
	 * Get the security name for the given subject.
	 * @param subject The subject for which to retrieve the security name
	 * @return String the security name for the given subject
	 */
	private static String getSecurityName(final Subject subject) {
		logger.debug(LogMessage.format("Determining Websphere security name for subject %s", subject));
		String userSecurityName = null;
		if (subject != null) {
			// SEC-803
			Object credential = subject.getPublicCredentials(getWSCredentialClass()).iterator().next();
			if (credential != null) {
				userSecurityName = (String) invokeMethod(getSecurityNameMethod(), credential);
			}
		}
		logger.debug(LogMessage.format("Websphere security name is %s for subject %s", subject, userSecurityName));
		return userSecurityName;
	}

	/**
	 * Get the current RunAs subject.
	 * @return Subject the current RunAs subject
	 */
	private static Subject getRunAsSubject() {
		logger.debug("Retrieving WebSphere RunAs subject");
		// get Subject: WSSubject.getCallerSubject ();
		return (Subject) invokeMethod(getRunAsSubjectMethod(), null, new Object[] {});
	}

	/**
	 * Get the WebSphere group names for the given subject.
	 * @param subject The subject for which to retrieve the WebSphere group names
	 * @return the WebSphere group names for the given subject
	 */
	private static List<String> getWebSphereGroups(final Subject subject) {
		return getWebSphereGroups(getSecurityName(subject));
	}

	/**
	 * Get the WebSphere group names for the given security name.
	 * @param securityName The security name for which to retrieve the WebSphere group
	 * names
	 * @return the WebSphere group names for the given security name
	 */
	@SuppressWarnings("unchecked")
	private static List<String> getWebSphereGroups(final String securityName) {
		Context context = null;
		try {
			// TODO: Cache UserRegistry object
			context = new InitialContext();
			Object objRef = context.lookup(USER_REGISTRY);
			Object userReg = invokeMethod(getNarrowMethod(), null, objRef,
					Class.forName("com.ibm.websphere.security.UserRegistry"));
			logger.debug(LogMessage.format("Determining WebSphere groups for user %s using WebSphere UserRegistry %s",
					securityName, userReg));
			final Collection<String> groups = (Collection<String>) invokeMethod(getGroupsForUserMethod(), userReg,
					new Object[] { securityName });
			logger.debug(LogMessage.format("Groups for user %s: %s", securityName, groups));
			return new ArrayList<String>(groups);
		}
		catch (Exception ex) {
			logger.error("Exception occured while looking up groups for user", ex);
			throw new RuntimeException("Exception occured while looking up groups for user", ex);
		}
		finally {
			closeContext(context);
		}
	}

	private static void closeContext(Context context) {
		try {
			if (context != null) {
				context.close();
			}
		}
		catch (NamingException ex) {
			logger.debug("Exception occured while closing context", ex);
		}
	}

	private static Object invokeMethod(Method method, Object instance, Object... args) {
		try {
			return method.invoke(instance, args);
		}
		catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException ex) {
			String message = "Error while invoking method " + method.getClass().getName() + "." + method.getName() + "("
					+ Arrays.asList(args) + ")";
			logger.error(message, ex);
			throw new RuntimeException(message, ex);
		}
	}

	private static Method getMethod(String className, String methodName, String[] parameterTypeNames) {
		try {
			Class<?> c = Class.forName(className);
			int len = parameterTypeNames.length;
			Class<?>[] parameterTypes = new Class[len];
			for (int i = 0; i < len; i++) {
				parameterTypes[i] = Class.forName(parameterTypeNames[i]);
			}
			return c.getDeclaredMethod(methodName, parameterTypes);
		}
		catch (ClassNotFoundException ex) {
			logger.error("Required class" + className + " not found");
			throw new RuntimeException("Required class" + className + " not found", ex);
		}
		catch (NoSuchMethodException ex) {
			logger.error("Required method " + methodName + " with parameter types (" + Arrays.asList(parameterTypeNames)
					+ ") not found on class " + className);
			throw new RuntimeException("Required class" + className + " not found", ex);
		}
	}

	private static Method getRunAsSubjectMethod() {
		if (getRunAsSubject == null) {
			getRunAsSubject = getMethod("com.ibm.websphere.security.auth.WSSubject", "getRunAsSubject",
					new String[] {});
		}
		return getRunAsSubject;
	}

	private static Method getGroupsForUserMethod() {
		if (getGroupsForUser == null) {
			getGroupsForUser = getMethod("com.ibm.websphere.security.UserRegistry", "getGroupsForUser",
					new String[] { "java.lang.String" });
		}
		return getGroupsForUser;
	}

	private static Method getSecurityNameMethod() {
		if (getSecurityName == null) {
			getSecurityName = getMethod("com.ibm.websphere.security.cred.WSCredential", "getSecurityName",
					new String[] {});
		}
		return getSecurityName;
	}

	private static Method getNarrowMethod() {
		if (narrow == null) {
			narrow = getMethod(PORTABLE_REMOTE_OBJECT_CLASSNAME, "narrow",
					new String[] { Object.class.getName(), Class.class.getName() });
		}
		return narrow;
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
		}
		catch (ClassNotFoundException ex) {
			logger.error("Required class " + className + " not found");
			throw new RuntimeException("Required class " + className + " not found", ex);
		}
	}

}
