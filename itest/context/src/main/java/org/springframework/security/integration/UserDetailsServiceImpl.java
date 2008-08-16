package org.springframework.security.integration;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.transaction.annotation.Transactional;

public class UserDetailsServiceImpl implements UserDetailsService{

	private UserRepository userRepository;
	
	@Transactional(readOnly=true)
	public UserDetails loadUserByUsername(String username) {
		return null;
	}

	@Required
	public void setUserRepository(UserRepository userRepository) {
		this.userRepository = userRepository;
	}
}