package org.springframework.security.integration;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration(locations={"/sec-933-app-context.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class SEC933ApplicationContextTests {

	@Autowired
	private UserDetailsService userDetailsService;
	
	@Test
	public void testSimpleApplicationContextBootstrap() throws Exception {
		assertNotNull(userDetailsService);
	}
}
