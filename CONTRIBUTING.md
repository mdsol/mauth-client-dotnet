# Contributing

## General Information
* Clone this repo in your workspace. Checkout latest `develop` branch.
* Make new changes or updates into `feature/bugfix` branch.
* Make sure to add unit tests for it so that there is no breaking changes.
* Commit and push your branch to compare and create PR against latest `develop` branch.

## Running Tests
To run tests, go the folder `mauth-client-dotnet\tests\Medidata.MAuth.Tests`
Next, run the tests as:

```
dotnet test
```

## Running mauth-protocol-test-suite
To run the mauth-protocol-test-suite clone the latest suite onto your machine and place it in the same parent directory as this repo (or supply the ENV var 
`TEST_SUITE_PATH` with the path to the test suite relative to this repo).  
Then navigate to :`mauth-client-dotnet\tests\Medidata.MAuth.Tests`  
And, run the tests as:

```
dotnet test --filter "FullyQualifiedName~MAuthProtocolSuiteTests"
```
