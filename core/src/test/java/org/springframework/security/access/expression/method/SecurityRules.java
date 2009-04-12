package org.springframework.security.access.expression.method;

public class SecurityRules {
    public static boolean disallow() {
        return false;
    }

    public static boolean allow() {
        return false;
    }

    public static boolean isJoe(String s) {
        return "joe".equals(s);
    }
}

