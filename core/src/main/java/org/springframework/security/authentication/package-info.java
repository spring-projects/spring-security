/**
 * Core classes and interfaces related to user authentication, which are used throughout Spring Security.
 * <p>
 * Of key importance is the {@link org.springframework.security.authentication.AuthenticationManager AuthenticationManager}
 * and its default implementation {@link org.springframework.security.authentication.ProviderManager
 * ProviderManager}, which maintains a list {@link org.springframework.security.authentication.AuthenticationProvider
 * AuthenticationProvider}s to which it delegates authentication requests.
 */
package org.springframework.security.authentication;
