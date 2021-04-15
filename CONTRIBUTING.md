# Contributing

## Cloning the Repo

This repo contains the submodule `mauth-protocol-test-suite` so requires a flag when initially cloning in order to clone and init submodules.

```
git clone --recurse-submodules git@github.com:mdsol/mauth-client-ruby.git
```

If you have already cloned a version of this repo before the submodule was introduced then run

```
cd mauth-protocol-test-suite
git submodule update --init
```

to init the submodule.

## General Information
* Checkout latest `develop` branch.
* Make new changes or updates into `feature/bugfix` branch.
* Make sure to add unit tests for it so that there is no breaking changes.
* Commit and push your branch to compare and create PR against latest `develop` branch.

## Running Tests
To run tests, go the folder `mauth-client-dotnet\tests\Medidata.MAuth.Tests`
Next, run the tests as:

```
dotnet test
```
