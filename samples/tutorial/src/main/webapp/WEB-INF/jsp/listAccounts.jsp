<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core"%>

<h1>Accounts</h1>

<a href="index.jsp">Home3</a><br><br>

<table>
<c:forEach var="account" items="${accounts}">
  <tr>
  <td>
      <c:out value="${account.id}"/>
  </td>
  <td>
      <c:out value="${account.holder}"/>
  </td>
  <td>
      <c:out value="${account.balance}"/>
  </td>
  <td>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=-20.00">-$20</a>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=-5.00">-$5</a>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=5.00">+$5</a>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=20.00">+$20</a>
  </td>
  </tr>
</c:forEach>
</table>