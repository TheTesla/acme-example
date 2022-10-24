# ACMEv2 Let's Encrypt demonstration

This python3 example shows, how to get a _Let's Encrypt_ certificate using the _ACMEv2_ API.

It is based on the example from the _acme_ library as part of the _certbot_ repository.

It doesn't use the _OpenSSL_ python package, because the authors of _certbot_ want to removethis dependency in future. We don't want to reintroduce a dependency in a simple exmaple, which will be intentionally removed from the library investing hard work.

## Author

Stefan Helmert

