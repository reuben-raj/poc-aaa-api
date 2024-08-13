# POC AAA API

Stacks for POC AAA API

## Useful commands

-   `npm run build` compile typescript to js
-   `npm run watch` watch for changes and compile
-   `npm run test` perform the jest unit tests
-   `cdk deploy` deploy this stack to your default AWS account/region
-   `cdk diff` compare deployed stack with current state
-   `cdk synth` emits the synthesized CloudFormation template

## Run and test locally

### To run locally via AWS SAM:

-   Open a terminal and run `sam build` to build the components
    -   Build components can be found in `.aws` folder for debugging and verification
-   Open a separate terminal and run `sam local start-api` to start a local APIGateway

You should be able to test the project on the following URL: http://127.0.0.1:3000

To hot reload, run `sam build`. Changes will be reflected in next invocation.

### To run regression tests:

-   Open the `acceptance-test` directory
-   Run `npm run build`
-   Run `npm run test`
-   To view the serenity reports, run `npm run start`

Serenity reports will automatically open a browser page to http://localhost:63343/

You can also view the reports by opening the `index.html` file located in `acceptance-test/target/site/serenity/index.html`