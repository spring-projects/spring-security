package org.springframework.security.config;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class PostProcessedMockUserDetailsService implements UserDetailsService {
    private String postProcessorWasHere;

    public PostProcessedMockUserDetailsService() {
        this.postProcessorWasHere = "Post processor hasn't been yet";
    }

    public String getPostProcessorWasHere() {
        return postProcessorWasHere;
    }

    public void setPostProcessorWasHere(String postProcessorWasHere) {
        this.postProcessorWasHere = postProcessorWasHere;
    }

    public UserDetails loadUserByUsername(String username) {
        throw new UnsupportedOperationException("Not for actual use");
    }
}
