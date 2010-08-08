package org.springframework.security.web;

/**
 * Well-known keys which are used to store Spring Security information in request or session scope.
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public final class WebAttributes {
    public static final String ACCESS_DENIED_403 = "SPRING_SECURITY_403_EXCEPTION";
    public static final String AUTHENTICATION_EXCEPTION = "SPRING_SECURITY_LAST_EXCEPTION";
    public static final String LAST_USERNAME = "SPRING_SECURITY_LAST_USERNAME";
}
