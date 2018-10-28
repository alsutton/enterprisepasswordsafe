# Enterprise Password Safe

## License

The Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk> and contributors

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

### Current Development State

This is very much pre-release. The code is undergoing significant and widespread
updates to modernise it's use of Java and current cryptographic best practices.

### What is it?

The Enterprise Password Safe was sold by several companies from the mid-2000's through to 2014 and was used by customers from small businesses to multi-nationals and parts of government agencies around the globe. It is a multi-user, audited password storage solution with user and group access controls.

### How does it work?

The Enterprise Password Safe (EPS) uses a cryptographic chain to enforce password access; A key is derived from the users password which decrypts a user specific AES key. The user key is then used to decrypt the AES keys for the groups the user belongs to, and then the users AES key and the AES keys of the groups they belong to, can be used to decrypt the RSA public key (for read access), and RSA private key (for write access) associated with a password.

The key pair for each password is different, and the keys are encrypted with each group or user AES key that have access rules for that password.

### More details

The EPS is written in Java and built using [Gradle](https://gradle.org). It uses JDBC to talk to the database which is used to store the information via a custom database abstraction layer which handles the translation of EPS requests into a database specific format. The EPS includes support for Apache Derby, DB2, HSQLDB, JavaDB, MySQL, Oracle 8i, Postgresql, and SQL Server.

The code can be deployed using Docker by running the following commands;

```bash
$ docker build -t eps:latest .
$ docker run -it --rm -p 8888:8080 eps:latest
```

Which run the EPS on the URL `http://localhost:8888/`.

### Contributions

Pull requests are welcome. If you're planning to implement a new feature or work on a change, please make sure you open an issue for it and comment that you're working on it to avoid multiple people working on the same thing and producing incompatible implementations.

## Quality Indicators

#### Build
[![CircleCI](https://circleci.com/gh/alsutton/enterprisepasswordsafe/tree/master.svg?style=svg)](https://circleci.com/gh/alsutton/enterprisepasswordsafe/tree/master)

#### Code Metrics
[![Maintainability](https://api.codeclimate.com/v1/badges/6b1eb77eaef47517d783/maintainability)](https://codeclimate.com/github/alsutton/enterprisepasswordsafe/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/6b1eb77eaef47517d783/test_coverage)](https://codeclimate.com/github/alsutton/enterprisepasswordsafe/test_coverage)

