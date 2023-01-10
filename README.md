# Action AWS IAM assume role

Action that allows for the `sts:AssumeRole` of an IAM role via the following methods:

- An IAM user with permission to assume the target IAM role using static access ID key/secret access key credentials (the old way).
- Via a [GitHub OpenID Connect identity provider](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) (OIDC), which avoids the need to handle static secrets (the new, preferred way 👌).

To keep things relatively simple, this [composite action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) uses the [AWS CLI](https://aws.amazon.com/cli/) for all AWS API operations and a [little Python](main.py) to handle execution/parsing responses and setting things up - all of which is pre-installed out of the box under [GitHub-hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners).

**Be aware:** designed for use under _Linux based runners_ only - doubtful this will get far under Windows. 😀

- [Usage](#usage)
	- [IAM user -> IAM role](#iam-user---iam-role)
	- [OpenID Connect (OIDC) IAM role](#openid-connect-oidc-iam-role)
	- [OpenID Connect (OIDC) IAM role -> Another IAM role](#openid-connect-oidc-iam-role---another-iam-role)
- [Reference](#reference)

## Usage

### IAM user -> IAM role

Given the following IAM user permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::ACCOUNT_ID:role/MY_TARGET_ROLE"
      ]
    }
  ]
}
```

...and the following IAM role trust relationship:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": [
          "arn:aws:iam::ACCOUNT_ID:user/MY_IAM_USER"
        ]
      }
    }
  ]
}
```

the following GitHub Actions workflow example would provide IAM assume of `arn:aws:iam::ACCOUNT_ID:role/MY_TARGET_ROLE`:

```yaml
jobs:
  main:
    name: IAM user -> IAM role
    runs-on: ubuntu-latest
    steps:
      - name: Assume role
        uses: magnetikonline/action-aws-iam-assume-role@v1
        with:
          user-access-key-id: ${{ secrets.IAM_USER_ACCESS_KEY_ID }}
          user-secret-access-key: ${{ secrets.IAM_USER_SECRET_ACCESS_KEY }}
          assume-role-arn: arn:aws:iam::ACCOUNT_ID:role/MY_TARGET_ROLE
          aws-region: ap-southeast-2
          # optional inputs
          # assume-role-duration-seconds: 6000
          # assume-role-session-name: GitHubActions

      # IAM role assumed via AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN
      - name: whoami
        run: aws sts get-caller-identity
```

### OpenID Connect (OIDC) IAM role

**Note:** assumes `arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com` has been previously configured as an OpenID Connect [AWS identity provider to GitHub](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services#adding-the-identity-provider-to-aws) with the following settings:

- Provider: `token.actions.githubusercontent.com`
- Audience: `https://github.com/ORGANIZATION_OR_USERNAME`

Given the following IAM role trust relationship:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Condition": {
        "StringLike": {
          "token.actions.githubusercontent.com:aud": "https://github.com/ORGANIZATION_OR_USERNAME",
          "token.actions.githubusercontent.com:sub": "repo:ORGANIZATION_OR_USERNAME/*"
        }
      }
    }
  ]
}
```

the following GitHub Actions workflow example would provide IAM assume of the OpenID Connect provider trusted IAM role:

```yaml
jobs:
  main:
    name: OpenID Connect (OIDC) IAM role
    runs-on: ubuntu-latest
    # note: permissions required to fetch OpenID Connect token and allow actions/checkout
    permissions:
      contents: read
      id-token: write
    steps:
      - name: Assume role
        uses: magnetikonline/action-aws-iam-assume-role@v1
        with:
          web-identity-role-arn: arn:aws:iam::ACCOUNT_ID:role/MY_TARGET_ROLE_WITH_OIDC_TRUST_RELATIONSHIP
          aws-region: ap-southeast-2
          # optional inputs
          # assume-role-duration-seconds: 6000
          # assume-role-session-name: GitHubActions

      # IAM role assumed via AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN
      - name: whoami
        run: aws sts get-caller-identity
```

### OpenID Connect (OIDC) IAM role -> Another IAM role

A slight spin on above, performing the following:

- First assume the OpenID Connect trusted IAM role.
- Next, assume _another_ IAM role via the OIDC trusted IAM role.

With the following _another_ IAM role trust relationship:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": [
          "arn:aws:iam::ACCOUNT_ID:role/MY_TARGET_ROLE_WITH_OIDC_TRUST_RELATIONSHIP"
        ]
      }
    }
  ]
}
```

the following GitHub Actions workflow example would provide IAM assume of OpenID Connect provider trusted IAM role -> final role. Note the use of _both_ `web-identity-role-arn` and `assume-role-arn` input arguments:

```yaml
jobs:
  main:
    name: OpenID Connect (OIDC) IAM role -> Another IAM role
    runs-on: ubuntu-latest
    # note: permissions required to fetch OpenID Connect token and allow actions/checkout
    permissions:
      contents: read
      id-token: write
    steps:
      - name: Assume role
        uses: magnetikonline/action-aws-iam-assume-role@v1
        with:
          web-identity-role-arn: arn:aws:iam::ACCOUNT_ID:role/MY_TARGET_ROLE_WITH_OIDC_TRUST_RELATIONSHIP
          assume-role-arn: arn:aws:iam::ACCOUNT_ID:role/MY_TARGET_ROLE_ASSUMED_FROM_OIDC_ROLE
          aws-region: ap-southeast-2
          # optional inputs
          # assume-role-duration-seconds: 6000
          # assume-role-session-name: GitHubActions

      # IAM role assumed via AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN
      - name: whoami
        run: aws sts get-caller-identity
```

## Reference

- https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html#idp_oidc_Create_GitHub
- https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sts/assume-role-with-web-identity.html
