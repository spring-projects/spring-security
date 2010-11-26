package org.springframework.security.web;

/**
 * Well-known keys which are used to store Spring Security information in request or session scope.
 *
 * @author Luke Taylor
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
    public static final String LAST_USERNAME = "SPRING_SECURITY_LAST_USERNAME";
}
