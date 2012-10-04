package org.springframework.security.web;

import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;

/**
 * Well-known keys which are used to store Spring Security information in request or session scope.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0.3
 */
public final class WebAttributes {
   /**
    * Used to cache an {@code AccessDeniedException} in the request for rendering.
    *
    * @see org.springframework.security.web.access.AccessDeniedHandlerImpl
    */
    public static final String ACCESS_DENIED_403 = "SPRING_SECURITY_403_EXCEPTION";

   /**
    * Used to cache an authentication-failure exception in the session.
    *
    * @see org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
    */
    public static final String AUTHENTICATION_EXCEPTION = "SPRING_SECURITY_LAST_EXCEPTION";

    /**
     * Set as a request attribute to override the default {@link WebInvocationPrivilegeEvaluator}
     *
     * @see WebInvocationPrivilegeEvaluator
     * @since 3.1.3
     */
    public static final String WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE = WebAttributes.class.getName() + ".WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE";
}
