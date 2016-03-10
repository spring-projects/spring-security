package org.springframework.security.config.http

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.WebAttributes

/**
 *
 * @author Luke Taylor
 */
class FormLoginBeanDefinitionParserTests extends AbstractHttpConfigTests {

	def 'form-login default login page'() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:'GET',requestURI:'/login')
			MockHttpServletResponse response = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
			httpAutoConfig {
				csrf(disabled:true)
			}
			createAppContext()
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<html><head><title>Login Page</title></head><body onload='document.f.username.focus();'>
<h3>Login with Username and Password</h3><form name='f' action='/login' method='POST'>
<table>
	<tr><td>User:</td><td><input type='text' name='username' value=''></td></tr>
	<tr><td>Password:</td><td><input type='password' name='password'/></td></tr>
	<tr><td colspan='2'><input name="submit" type="submit" value="Login"/></td></tr>
</table>
</form></body></html>"""
	}

	def 'form-login default login page custom attributes'() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:'GET',requestURI:'/login')
			MockHttpServletResponse response = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
			httpAutoConfig {
				'form-login'('login-processing-url':'/login_custom','username-parameter':'custom_user','password-parameter':'custom_password')
				csrf(disabled:true)
			}
			createAppContext()
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<html><head><title>Login Page</title></head><body onload='document.f.custom_user.focus();'>
<h3>Login with Username and Password</h3><form name='f' action='/login_custom' method='POST'>
<table>
	<tr><td>User:</td><td><input type='text' name='custom_user' value=''></td></tr>
	<tr><td>Password:</td><td><input type='password' name='custom_password'/></td></tr>
	<tr><td colspan='2'><input name="submit" type="submit" value="Login"/></td></tr>
</table>
</form></body></html>"""
	}

	def 'openid-login default login page'() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:'GET',requestURI:'/login')
			MockHttpServletResponse response = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
			httpAutoConfig {
				'openid-login'()
				csrf(disabled:true)
			}
			createAppContext()
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<html><head><title>Login Page</title></head><body onload='document.f.username.focus();'>
<h3>Login with Username and Password</h3><form name='f' action='/login' method='POST'>
<table>
	<tr><td>User:</td><td><input type='text' name='username' value=''></td></tr>
	<tr><td>Password:</td><td><input type='password' name='password'/></td></tr>
	<tr><td colspan='2'><input name="submit" type="submit" value="Login"/></td></tr>
</table>
</form><h3>Login with OpenID Identity</h3><form name='oidf' action='/login/openid' method='POST'>
<table>
	<tr><td>Identity:</td><td><input type='text' size='30' name='openid_identifier'/></td></tr>
	<tr><td colspan='2'><input name="submit" type="submit" value="Login"/></td></tr>
</table>
</form></body></html>"""
	}

	def 'openid-login default login page custom attributes'() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:'GET',requestURI:'/login')
			MockHttpServletResponse response = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
			httpAutoConfig {
				'openid-login'('login-processing-url':'/login_custom')
				csrf(disabled:true)
			}
			createAppContext()
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<html><head><title>Login Page</title></head><body onload='document.f.username.focus();'>
<h3>Login with Username and Password</h3><form name='f' action='/login' method='POST'>
<table>
	<tr><td>User:</td><td><input type='text' name='username' value=''></td></tr>
	<tr><td>Password:</td><td><input type='password' name='password'/></td></tr>
	<tr><td colspan='2'><input name="submit" type="submit" value="Login"/></td></tr>
</table>
</form><h3>Login with OpenID Identity</h3><form name='oidf' action='/login_custom' method='POST'>
<table>
	<tr><td>Identity:</td><td><input type='text' size='30' name='openid_identifier'/></td></tr>
	<tr><td colspan='2'><input name="submit" type="submit" value="Login"/></td></tr>
</table>
</form></body></html>"""
	}

	def 'form-login forward authentication failure handler'() {
		setup:
		MockHttpServletRequest request = new MockHttpServletRequest(method:'POST',servletPath:'/login')
		request.setParameter("username", "bob")
		request.setParameter("password", "invalidpassword")
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		httpAutoConfig {
			'form-login'('authentication-failure-forward-url':'/failure_forward_url')
			csrf(disabled:true)
		}
		createAppContext()
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.getStatus() == 200
		response.forwardedUrl == "/failure_forward_url"
		request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) != null;
	}

	def 'form-login forward authentication success handler'() {
		setup:
		MockHttpServletRequest request = new MockHttpServletRequest(method:'POST',servletPath:'/login')
		request.setParameter("username", "bob")
		request.setParameter("password", "bobspassword")
		MockHttpServletResponse response = new MockHttpServletResponse()
		MockFilterChain chain = new MockFilterChain()
		httpAutoConfig {
			'form-login'('authentication-success-forward-url':'/success_forward_url')
			csrf(disabled:true)
		}
		createAppContext()
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then:
		response.getStatus() == 200
		response.forwardedUrl == "/success_forward_url"
	}
}
