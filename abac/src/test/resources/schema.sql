CREATE TABLE abac (
  id INTEGER PRIMARY KEY auto_increment,
  name VARCHAR(200) NOT NULL,
  description VARCHAR(200) NULL,
  type VARCHAR(200) NULL,
  applicable VARCHAR(200) NULL,
  condition VARCHAR(200) NOT NULL
);