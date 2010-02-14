/**
 * Classes related to the establishment of a security context for the duration of a request (such as
 * an HTTP or RMI invocation).
 * <p>
 * A security context is usually associated with the current execution thread for the duration of the request,
 * making the authentication information it contains available throughout all the layers of an application.
 * <p>
 * The {@link org.springframework.security.core.context.SecurityContext SecurityContext} can be accessed at any point
 * by calling the {@link org.springframework.security.core.context.SecurityContextHolder SecurityContextHolder}.
 */
package org.springframework.security.core.context;
