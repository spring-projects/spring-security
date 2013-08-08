/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.session;

import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.support.BeanDefinitionValidationException;
import org.springframework.security.core.Authentication;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * Enum that determines how session fixation protection is applied to a successful authentication. Currently, supported
 * schemes are no protection, a new session with only Spring attributes migrated, a new session with all attributes
 * migrated, and use of {@code HttpServletRequest#changeSessionId} (in Servlet 3.1 and newer containers only).
 *
 * @author Luke Taylor
 * @author Nicholas Williams
 * @since 3.2
 * @see SessionFixationProtectionSchemeStrategy
 * @see ConcurrentSessionFixationProtectionSchemeStrategy
 */
public enum SessionFixationProtectionScheme {
    /**
     * No session fixation protection will be applied. {@link #applySessionFixationProtection} will throw an
     * {@link UnsupportedOperationException}, so a scheme should always be checked for inequality to {@code NONE}
     * before calling {@link #applySessionFixationProtection}.
     */
    NONE("none") {
        @Override
        void applySessionFixationProtection(Authentication authentication, HttpServletRequest request) {
            throw new UnsupportedOperationException("Session fixation protection is not supported.");
        }
    },

    /**
     * Invalidates the existing session, creates a new session, and migrates only Spring Security-related session
     * attributes to the new session. This approach will only be effective if your servlet container always assigns a
     * new session ID when a session is invalidated and a new session created by calling
     * {@link HttpServletRequest#getSession()}. Also, this scheme is susceptible to the issues with
     * {@link javax.servlet.http.HttpSessionBindingListener} as noted in the documentation for
     * {@link SessionFixationProtectionSchemeStrategy}.
     */
    NEW_SESSION("newSession") {
        @Override
        void applySessionFixationProtection(Authentication authentication, HttpServletRequest request) {
            migrateSession(request, true);
        }
    },

    /**
     * Invalidates the existing session, creates a new session, and migrates all session attributes to the new session.
     * This approach will only be effective if your servlet container always assigns a new session ID when a session is
     * invalidated and a new session created by calling {@link HttpServletRequest#getSession()}. Also, this scheme is
     * susceptible to the issues with {@link javax.servlet.http.HttpSessionBindingListener} as noted in the
     * documentation for {@link SessionFixationProtectionSchemeStrategy}. This is the default value in
     * Servlet 3.0 or older containers.
     */
    MIGRATE_SESSION("migrateSession") {
        @Override
        void applySessionFixationProtection(Authentication authentication, HttpServletRequest request) {
            migrateSession(request, false);
        }
    },

    /**
     * Calls {@code HttpServletRequest#changeSessionId()} to apply the container-provided session fixation protection.
     * This is the safest and most ideal solution, and avoids any problems with
     * {@link javax.servlet.http.HttpSessionBindingListener}. As such, this is the default value in Servlet 3.1 and
     * newer containers. However, if you are using an older Servlet container you cannot use this option.
     */
    CHANGE_SESSION_ID("changeSessionId") {
        @Override
        public void checkSchemeValidForContext() {
            if (CHANGE_SESSION_ID_METHOD == null) {
                throw new BeanDefinitionValidationException(
                        "The session fixation protection scheme 'changeSessionId' is only valid in Servlet 3.1 " +
                                "containers."
                );
            }
        }

        @Override
        void applySessionFixationProtection(Authentication authentication, HttpServletRequest request) {
            if (CHANGE_SESSION_ID_METHOD == null) {
                throw new IllegalStateException(
                        "The session fixation protection scheme 'changeSessionId' is only valid in Servlet 3.1 " +
                                "containers."
                );
            }
            ReflectionUtils.invokeMethod(CHANGE_SESSION_ID_METHOD, request);
        }
    };

    /**
     * A map of {@code session-fixation-protection} namespace configuration attribute values to schemes.
     */
    private static final Map<String, SessionFixationProtectionScheme> NAMESPACE_VALUES =
            new Hashtable<String, SessionFixationProtectionScheme>(4);

    /**
     * The {@code HttpServletRequest#changeSessionId()} method or null if this is a Servlet 3.0 or older container.
     */
    private static final Method CHANGE_SESSION_ID_METHOD =
            ClassUtils.getMethodIfAvailable(HttpServletRequest.class, "changeSessionId");

    static {
        for (SessionFixationProtectionScheme scheme : SessionFixationProtectionScheme.values()) {
            NAMESPACE_VALUES.put(scheme.namespaceValue, scheme);
        }
    }

    private final String namespaceValue;

    /**
     * Constructs a scheme with its {@code session-fixation-protection} namespace configuration attribute value.
     *
     * @param namespaceValue the namespace value.
     */
    private SessionFixationProtectionScheme(String namespaceValue) {
        this.namespaceValue = namespaceValue;
    }

    /**
     * Checks whether the scheme is valid for the current context and throws a {@link BeanDefinitionValidationException}
     * if it is not valid. This is called at configuration time to ensure that the container is Servlet 3.1 if
     * {@link #CHANGE_SESSION_ID} is chosen.
     *
     * @throws BeanDefinitionValidationException if the scheme is not valid for the current context.
     */
    public void checkSchemeValidForContext() {
        // usually valid, do nothing
    }

    /**
     * Applies session fixation protection as appropriate for this scheme. Throws {@link UnsupportedOperationException}
     * for {@link #NONE}.
     *
     * @param authentication The authentication object.
     * @param request The current request.
     * @throws UnsupportedOperationException if called on {@link #NONE}.
     */
    abstract void applySessionFixationProtection(Authentication authentication, HttpServletRequest request);

    /**
     * Gets the session fixation protection scheme that corresponds with the {@code session-fixation-protection}
     * namespace configuration attribute. If an unrecognized attribute value is specified, this returns {@code null}.
     *
     * @param attributeValue The configuration value specified in the namespace attribute.
     * @return the scheme that corresponds with the specified namespace attribute value.
     */
    public static SessionFixationProtectionScheme getFromNamespaceAttribute(String attributeValue) {
        return NAMESPACE_VALUES.get(attributeValue);
    }

    /**
     * Gets the default session fixation protection scheme. In a Servlet 3.1 or newer container, this is
     * {@link #CHANGE_SESSION_ID}. In older containers, it is {@link #MIGRATE_SESSION}.
     *
     * @return the default session fixation protection scheme.
     */
    public static SessionFixationProtectionScheme getDefault() {
        return CHANGE_SESSION_ID_METHOD != null ? CHANGE_SESSION_ID : MIGRATE_SESSION;
    }

    private static void migrateSession(HttpServletRequest request, boolean springSecurityAttributesOnly) {
        HttpSession session = request.getSession();
        Map<String, Object> extractedAttributes = new HashMap<String, Object>();

        Enumeration<String> attributeNames = session.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            String name = attributeNames.nextElement();
            if (!springSecurityAttributesOnly || name.startsWith("SPRING_SECURITY_")) {
                extractedAttributes.put(name, session.getAttribute(name));
            }
        }

        session.invalidate();
        session = request.getSession(true);

        for (Map.Entry<String, Object> entry : extractedAttributes.entrySet()) {
            session.setAttribute(entry.getKey(), entry.getValue());
        }
    }
}
