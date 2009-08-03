package org.springframework.security.config;

public abstract class ConfigTestUtils {
    public static final String AUTH_PROVIDER_XML =
        "<authentication-manager alias='authManager'>" +
        "    <authentication-provider>" +
        "        <user-service id='us'>" +
        "            <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
        "            <user name='bill' password='billspassword' authorities='ROLE_A,ROLE_B,AUTH_OTHER' />" +
        "            <user name='admin' password='password' authorities='ROLE_ADMIN,ROLE_USER' />" +
        "            <user name='user' password='password' authorities='ROLE_USER' />" +
        "        </user-service>" +
        "    </authentication-provider>" +
        "</authentication-manager>";
}
