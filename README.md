

## Install

1. Install the dependencies
```sh
npm i
```

2. Replace argument in main() function of index.js with the path of the PDF you want to verify.

3. Run pdf verification script
```sh
npm start
```

If all goes well, your PDF should be verified :)


Check cerficiate expirty date with OpenSSL
```sh
openssl x509 -in personal.pem -text -noout | grep -i not
```

Has spreadsheet which can be access on request
https://www.facultyoffice.org.uk/notaries/customers/access-to-data/
