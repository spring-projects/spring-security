package org.springframework.security.access.annotation;

import org.springframework.security.access.SecurityConfig;

import javax.annotation.security.PermitAll;
import javax.annotation.security.DenyAll;

/**
 * Security config applicable as a JSR 250 annotation attribute.
 *
 * @author Ryan Heaton
 * @since 2.0
 */
public class Jsr250SecurityConfig extends SecurityConfig {
    public static final Jsr250SecurityConfig PERMIT_ALL_ATTRIBUTE = new Jsr250SecurityConfig(PermitAll.class.getName());
    public static final Jsr250SecurityConfig DENY_ALL_ATTRIBUTE = new Jsr250SecurityConfig(DenyAll.class.getName());

    public Jsr250SecurityConfig(String role) {
        super(role);
    }

}