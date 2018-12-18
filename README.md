# GoPOC (Golang Proof of concept checker) Beta version

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e1b04411f33d4883a048e73a91a6d7bc)](https://app.codacy.com/app/MonaxGT/gopoc?utm_source=github.com&utm_medium=referral&utm_content=MonaxGT/gopoc&utm_campaign=Badge_Grade_Dashboard)

Tools for check pocs vulnerabilities

### Example yaml-rule

```
poc:
  - module: metadata
    parameter:
        cvss: 1
        author: Author
  - name: Name
    description: Description
    module: http
    parameter:
      url: 'https://google.com/'
      method: GET
      headers:
        User-Agent: Firefox
      expect_response_code: 200
    time: 2017-11-15
    case: 100
```

### Example run tool

```shell
cd cmd/
go run main.go -f test.yaml
```

You receive answer in bool format


You can use -v flag for additional information with req and resp header and body:

```
Loaded file: test.yaml
Result 0
 test №1 Yandex
Author:Makhinov Alex
CVSS:1.000000
--//--
```


P.S. This project was developed for backward compatibility with the project [explo](https://github.com/dtag-dev-sec/explo), but with some updates like one session with cookie in Jar between 2 query in one yaml-rule.

TODO:
* 1) Add all functional from explo-tool
* 2) Add selenium module for complicated request