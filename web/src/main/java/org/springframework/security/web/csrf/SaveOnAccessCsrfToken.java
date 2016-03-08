package org.springframework.security.web.csrf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@SuppressWarnings("serial")
final class SaveOnAccessCsrfToken implements CsrfToken {
    private transient CsrfTokenRepository tokenRepository;
    private transient HttpServletRequest request;
    private transient HttpServletResponse response;

    private final CsrfToken delegate;

    public SaveOnAccessCsrfToken(CsrfTokenRepository tokenRepository,
                                 HttpServletRequest request, HttpServletResponse response,
                                 CsrfToken delegate) {
        this.tokenRepository = tokenRepository;
        this.request = request;
        this.response = response;
        this.delegate = delegate;
    }

    public String getHeaderName() {
        return delegate.getHeaderName();
    }

    public String getParameterName() {
        return delegate.getParameterName();
    }

    public String getToken() {
        saveTokenIfNecessary();
        return delegate.getToken();
    }

    @Override
    public String toString() {
        return "SaveOnAccessCsrfToken [delegate=" + delegate + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((delegate == null) ? 0 : delegate.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SaveOnAccessCsrfToken other = (SaveOnAccessCsrfToken) obj;
        if (delegate == null) {
            if (other.delegate != null)
                return false;
        } else if (!delegate.equals(other.delegate))
            return false;
        return true;
    }

    private void saveTokenIfNecessary() {
        if (this.tokenRepository == null) {
            return;
        }

        synchronized (this) {
            if (tokenRepository != null) {
                this.tokenRepository.saveToken(delegate, request, response);
                this.tokenRepository = null;
                this.request = null;
                this.response = null;
            }
        }
    }
}
