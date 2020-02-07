<html>
<body>
<h1>Secure Page</h1>
<p>This is a protected page. You can get to me if you've been remembered,
or if you've authenticated this session.</p>

<%if (request.isUserInRole("ROLE_SUPERVISOR")) { %>
    <p>You are a supervisor! You can therefore see the <a href="extreme/index.jsp">extremely secure page</a>.</p>
<% } %>

<p><a id="home" href="../">Home</a>
<p><a id="proxy" href="ptSample">Proxy Ticket Sample page</a></p>
<p><a id="logout" href="../logout">Logout</a>
</body>
</html>
