<%@taglib prefix="c" uri="https://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<html>
<head><title>Secure Page</title></head>
<body>
<h1>Secure Page</h1>
This is a protected page. You can get to me if you've been remembered,
or if you've authenticated this session.<br><br>

<%if (request.isUserInRole("ROLE_SUPERVISOR")) { %>
	You are a supervisor! You can therefore see the <a href="extreme/index.jsp">extremely secure page</a>.<br><br>
<% } %>


<p><a href="../">Home</a>
<form action="<c:url value="/logout"/>" method="post">
<input type="submit" value="Logoff"/> (also clears any remember-me cookie)
<security:csrfInput/>
</form>
</body>
</html>