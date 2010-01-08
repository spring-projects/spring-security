package org.springframework.security.web.authentication.rememberme;

import java.util.Date;

/**
 * @author Luke Taylor
 */
public class PersistentRememberMeToken {
    private String username;
    private String series;
    private String tokenValue;
    private Date date;

    public PersistentRememberMeToken(String username, String series, String tokenValue, Date date) {
        this.username = username;
        this.series = series;
        this.tokenValue = tokenValue;
        this.date = date;
    }

    public String getUsername() {
        return username;
    }

    public String getSeries() {
        return series;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public Date getDate() {
        return date;
    }
}
