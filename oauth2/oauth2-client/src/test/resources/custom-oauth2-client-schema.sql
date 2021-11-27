CREATE TABLE oauth2AuthorizedClient (
  clientRegistrationId varchar(100) NOT NULL,
  principalName varchar(200) NOT NULL,
  accessTokenType varchar(100) NOT NULL,
  accessTokenValue blob NOT NULL,
  accessTokenIssuedAt timestamp NOT NULL,
  accessTokenExpiresAt timestamp NOT NULL,
  accessTokenScopes varchar(1000) DEFAULT NULL,
  refreshTokenValue blob DEFAULT NULL,
  refreshTokenIssuedAt timestamp DEFAULT NULL,
  createdAt timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
  PRIMARY KEY (clientRegistrationId, principalName)
);
