package org.springframework.security.core;

/**
 * Indicates that the implementing object contains sensitive data, which can be erased using the
 * {@code eraseCredentials} method. Implementations are expected to invoke the method on any internal objects
 * which may also implement this interface.
 * <p>
 * For internal framework use only. Users who are writing their own {@code AuthenticationProvider} implementations
 * should create and return an appropriate {@code Authentication} object there, minus any sensitive data,
 * rather than using this interface.
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public interface CredentialsContainer {
    void eraseCredentials();
}
