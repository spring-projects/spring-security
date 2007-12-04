<html>
<body>
<h1>Secure Page</h1>
This is a protected page. You can get to me if you've been remembered,
or if you've authenticated this session.<br><br>

<%if (request.isUserInRole("ROLE_SUPERVISOR")) { %>
	You are a supervisor! You can therefore see the <a href="extreme/index.jsp">extremely secure page</a>.<br><br>
<% } %>


<p><a href="../">Home</a>
<p><a href="../j_spring_security_logout">Logout</a>
</body>
</html>