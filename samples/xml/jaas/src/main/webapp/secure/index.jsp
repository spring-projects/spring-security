<%@ taglib prefix="c" uri="https://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ page import="javax.security.auth.Subject" %>
<%@ page import="java.security.AccessController" %>
<%@ page import="org.springframework.security.core.context.SecurityContextHolder" %>
<%@ page import="org.springframework.security.core.Authentication" %>
<%@ page import="org.springframework.security.core.GrantedAuthority" %>

<html>
<head>
<title>Security Debug Information</title>
</head>
<body>

<h3>Security Debug Information</h3>

<% 

		Subject subject = Subject.getSubject(AccessController.getContext());  
		if(subject != null) { %>
<p>
			Subject.getSubject(AccessController.getContext()) is....: <%= subject %>
</p>
		<%} %>

<%
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) { %>
<p>
            Authentication object is of type: <em><%= auth.getClass().getName() %></em>
</p>
<p>
            Authentication object as a String: <br/><br/><%= auth.toString() %>
</p>

            Authentication object holds the following granted authorities:<br /><br />
<%
            for (GrantedAuthority authority : auth.getAuthorities()) { %>
                <%= authority %> (<em>getAuthority()</em>: <%= authority.getAuthority() %>)<br />
<%			}
%>

                <p><b>Success! Your web filters appear to be properly configured!</b></p>
<%
        } else {
%>
            Authentication object is null.<br />
            This is an error and your Spring Security application will not operate properly until corrected.<br /><br />
<%		}
%>

<form action="<c:url value="/logout"/>" method="post">
    <input type="submit" value="Log Out"/>
    <sec:csrfInput/>
</form>

</body>
</html>
