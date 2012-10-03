package org.springframework.security.config.http;


/**
 * Stores the default order numbers of all Spring Security filters for use in configuration.
 *
 * @author Luke Taylor
 */

enum SecurityFilters {
    FIRST (Integer.MIN_VALUE),
    CHANNEL_FILTER,
    SECURITY_CONTEXT_FILTER,
    CONCURRENT_SESSION_FILTER,
    LOGOUT_FILTER,
    X509_FILTER,
    PRE_AUTH_FILTER,
    CAS_FILTER,
    FORM_LOGIN_FILTER,
    OPENID_FILTER,
    LOGIN_PAGE_FILTER,
    DIGEST_AUTH_FILTER,
    BASIC_AUTH_FILTER,
    REQUEST_CACHE_FILTER,
    SERVLET_API_SUPPORT_FILTER,
    JAAS_API_SUPPORT_FILTER,
    REMEMBER_ME_FILTER,
    ANONYMOUS_FILTER,
    SESSION_MANAGEMENT_FILTER,
    EXCEPTION_TRANSLATION_FILTER,
    FILTER_SECURITY_INTERCEPTOR,
    SWITCH_USER_FILTER,
    LAST (Integer.MAX_VALUE);

    private static final int INTERVAL = 100;
    private final int order;

    private SecurityFilters() {
        order = ordinal() * INTERVAL;
    }

    private SecurityFilters(int order) {
        this.order = order;
    }

    public int getOrder() {
       return order;
    }
}
