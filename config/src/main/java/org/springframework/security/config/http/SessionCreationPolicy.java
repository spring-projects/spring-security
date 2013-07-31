package org.springframework.security.config.http;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;

/**
 * Specifies the various session creation policies for Spring Security.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public enum SessionCreationPolicy {
    /** Always create an {@link HttpSession} */
    ALWAYS,
    /** Spring Security will never create an {@link HttpSession}, but will use the {@link HttpSession} if it already exists */
    NEVER,
    /** Spring Security will only create an {@link HttpSession} if required */
    IF_REQUIRED,
    /** Spring Security will never create an {@link HttpSession} and it will never use it to obtain the {@link SecurityContext} */
    STATELESS
}
