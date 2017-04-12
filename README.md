# WebHooker
WebHooker handles GitHub `push` and `ping` webhooks right now. Supports validation with `X-Hub-Signature` from GitHub.

Generate a secret key however you want. Using `uuidgen` is a good solution.

Proxy pass to WebHooker from your webserver, WAF, etc. Follow whatever instructions are appropriate for your situation.

## Config
The configuration file, `webhooker.json` is `json` formatted text. When running a script it must be marked executable and prefixed with the full path or `./` if in the same directory.

Repositories are in the `"username/repository-name"`

Commands must be in the format `["command", "arg1", "arg2"...]`. Using `"` in an argument must be escaped like `\"`.
```json
{
        "username/some-repository": {
                "secret": "yoursecretkey",
                "push": {
                        "master": {
                                "command": ["sh", "-e", "example.sh"]
                        },
                        "development": {
                                "command": ["./example.sh"]
                        },
                        "config": {
                                "command": ["service", "nginx", "reload"]
                        }
                }
        }
}
```
