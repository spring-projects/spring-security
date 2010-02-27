package org.springframework.security.config.http;

/**
 *
 * @author Luke Taylor
 * @since 3.1
 */
enum SessionCreationPolicy {
    always,
    never,
    ifRequired,
    stateless
}
