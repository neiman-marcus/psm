![logo](https://github.com/neiman-marcus/psm/raw/master/images/logo.png "Neiman Marcus")

# psm

![version](https://img.shields.io/badge/version-v1.0.0-green.svg?style=flat) ![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat)

Security enabled simple REST service to manage application configuration in AWS SSM Parameter Store.

## Details

Cloud applications often require runtime and deployment configuration which must be managed. Following infrastructure-as-code best practices, storing this configuration alongside the application is crucial. 

Psm, short for *parameter store manager*, aims to allow product teams, developers, and cloud architects to easily maintain and deploy configuration in a secure, reliable, and templated manner, inside source control.

Deployed with serverless framework, this application can be easily modified for any AWS environment. If you have an improvement or run into an issue please participate on the github page.

## Configuration Convention

Psm assumes that application configuration is stored in a specific heirarchy in AWS SSM Parameter Store. By default psm deploys and handles configuration under `/{application}/{stage}/...` with each application or service having multiple stages for different environments. It is common to have a `dev`, `staging` and `prod` stage of an application.

## Psm functions

Psm uses the following three lambda functions:

* Encrypt - Encrypt secrets via KMS CMK to securely store in source control.
* Update - Update configuration in AWS SSM Parameter Store
* View - Retrieve and view configuration in AWS SSM Parameter Store

### Encrypt

The `encrypt` function allows a developer to encrypt a supplied value for storage in source control. The function takes the input and encrypts it against psm's CMK. The returned value is prefixed with `cipher:` and is used when pushing configuration to parameter store. It is not necessary to encrypt all values in source control, only secrets.

You have the option to `POST` a secret to be encrypted, or to use the `GET` method for a encrypted, randomly generated value.

This function requires no API key.

#### Examples

Example API calls and `.http` files can be used with the REST VSCode Extension.

##### POST Method

```HTTP
POST https://abcdef0123.execute-api.us-west-2.amazonaws.com/prod/encrypt HTTP/1.1

Hello World!
```

##### GET Method

```HTTP
GET https://abcdef0123.execute-api.us-west-2.amazonaws.com/prod/encrypt HTTP/1.1
```

#### Example Configuration File

```JSON
{
  "foo": "cipher:AQICAHjumw2gwZTBa2YnLcaUczMcoU..."
}
```

### Update

The `update` function pushes configuration to SSM Parameter Store. It will crawl the json formatted data input, and if configuration is changed, push the new configuration. If the value is encrypted, using the `encrypt` function, and prefixed with `cipher:`, it will decrypt the value before comparing the parameters.

The `update` function uses query string parameters to place the configuration. Psm is looking for the `appId` or name of the application, and `stage`. See examples below.

This function flattens the json input data. For example, `{"foo": {"bar": "buzz"}}` will be transformed to the parameter key, `/{application}/{stage}/foo.bar`.

This function requires use of the API key.

#### Metadata and Tags

You can include tags by including a dedicated `metadata.tags` section at the top level of the data input. The application will tag each parameter accordingly. It is advisable to keep tags at a minimum to avoid timeouts, and avoid too many tags which loses much of the value tags provide.

Tags resides within metadata, to provide future extensibility within the metadata heirarchy.

To disable maintaining metadata in SSM Parameter Store, supply the `--metadataAsParam false` cli option when deploying.

#### Examples

```HTTP
POST https://abcdef0123.execute-api.us-west-2.amazonaws.com/prod/update?appId=psm-test&stage=dev HTTP/1.1
x-api-key: abcdef0123456789ABCDEF0123456789abcdef01

{
    "metadata": {
        "tags": {
            "Application": "Application1",
            "Environment": "dev",
            "Owner": "admin@foo.io"
        }
    },
    "foo": {
        "bar": "buzz"
    },
    "baz": "cipher:AQICAHjumw2gwZTBa2YnLcaUczMcoU..."
}
```

```SHELL
curl -X POST 'https://abcdef0123.execute-api.us-west-2.amazonaws.com/prod/update?appId=psm-test&stage=dev' \
  -H 'x-api-key: abcdef0123456789ABCDEF0123456789abcdef01' \
  -d 'config/dev.json'
```

### View

The `view` function will retrieve the configuration from parameter store, for review. `SecureString` parameters are encrypted with the CMK during the process. Similar to the `update` function, the `view` function leverages query string parameters, which are `appId` and `stage`.

This function requires use of the API key.

#### Example

```HTTP
GET https://abcdef0123.execute-api.us-west-2.amazonaws.com/prod/view?appId=psm-test&stage=dev HTTP/1.1
x-api-key: abcdef0123456789ABCDEF0123456789abcdef01
```

## Installation && Deployment

* Install the necessary sls plugins with `npm install`.
* Install the necessary python requirements `pip install -r requirements.txt`.
* Deploy with `serverless deploy --stage prod`

## Usage

Developers may start encrypting their secrets with the `encrypt` function and push configuration to source control after deployment.

Next, within deployment pipelines, the build server should look for configuration files to push with each stage. For example, the repository can have a config directory, with json files for each stage. Example: `./config/{stage}.json`, or `./config/dev.json` and `/config/prod.json`.

The pipeline can make simple REST calls to put the parameters within those files, calling the `update` function. Use parameters in your pipeline to pass in the `appId` and `stage`. Neiman Marcus matches the `appId` to the repository name.

### Sererless Framework

Serverless Framework is one of the tools that can leverage these parameters from SSM Parameter Store. It is common to push configuration to SSM Parameter Store, and then immediately call it when deploying. Local configuration files can be used with Serverless Framework, but would not leverage secret storage.

#### Example

* With the above example

```YAML
provider:
  environment:
    FOO: ${ssm:/${self:service}/${self:provider.stage}/foo.bar}
    SECRET: ${ssm:/${self:service}/${self:provider.stage}/baz~true}
```

### Query String Parameters

| parameter | Description | Required |
| --- | --- | --- |
| appId | The name of the application or service to prefix parameters with. | yes |
| stage | The name of the stage to prefix parameters with. | yes |

## Security

* The encrypt function does not require an API key since it is fairly simple and non-impacting.
* The update and view functions require API keys.
* The API key should be stored securely within your build server's credential store and not shared.
* It is suggested that you modify the ApiGatewayRestApi to white list specific IP addresses if possible. Alternatively you can run the Api Gateway as a private endpoint.
* Update the `KMSKeyAdminRoles.yml` configuration file with the appropriate IAM roles to manange the CMK.

## Known issues

* Suppliying a list will map each item in the list to it's index.
  * For example, itme `{"foo": ["bar", "baz"]}` will be flattened to `/{application}/{stage}/foo.0` and `/{application}/{stage}/foo.1` with the value of `bar` and `baz` respectedly.
  * The `view` function will return the parameters as `{"foo": {"0": bar", "1": baz"}}`
  * It is best to avoid lists in the mean time.
* StringLists are not currently supported.

## Items to Add

* Optional parameter clean up
* SSM Parameter Store backup and logging of changes
* Better error handling
* String Lists

## Authors

* [**Clay Danford**](mailto:clay_danford@neimanmarcus.com) - Project creation and development.

## Conduct / Contributing / License

* Refer to our contribution guidelines to contribute to this project. See [CONTRIBUTING.md](https://github.com/neiman-marcus/terraform-aws-jenkins-ha-agents/tree/master/CONTRIBUTING.md).
* All contributions must follow our code of conduct. See [CONDUCT.md](https://github.com/neiman-marcus/terraform-aws-jenkins-ha-agents/tree/master/CONDUCT.md).
* This project is licensed under the Apache 2.0 license. See [LICENSE](https://github.com/neiman-marcus/terraform-aws-jenkins-ha-agents/tree/master/LICENSE).
