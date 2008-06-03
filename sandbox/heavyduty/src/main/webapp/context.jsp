<%@page import="org.springframework.web.context.support.WebApplicationContextUtils"%>
<%@page import="org.springframework.security.providers.ldap.LdapAuthenticationProvider"%>
<%@page import="org.springframework.security.providers.ProviderManager"%>

<html>
<body>
<h1>Context Information Page</h1>
<p>
LdapAuthenticationProvider instances: <br/>

<%=
WebApplicationContextUtils.getRequiredWebApplicationContext(
        session.getServletContext()).getBeansOfType(LdapAuthenticationProvider.class)
%>
</p>

<p>
Providers: <br />

<%=
((ProviderManager)WebApplicationContextUtils.getRequiredWebApplicationContext(
        session.getServletContext()).getBean("_authenticationManager")).getProviders() %>
</p>



<p><a href="/index.jsp">Home</a></p>
</body>
</html>