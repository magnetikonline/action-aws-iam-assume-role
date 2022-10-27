#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Dict, Tuple


def exit_error(message: str):
    print("::error ::" + message.strip().replace("\n", "%0A"))
    sys.exit(1)


def mask_value(value: str):
    print("::add-mask::" + value)


def read_inputs() -> Tuple[str, str, str, str, str, str, str]:
    def _env(key: str) -> str:
        return os.environ.get(key, "").strip()

    user_access_key_id = _env("INPUT_USER_ACCESS_KEY_ID")
    user_secret_access_key = _env("INPUT_USER_SECRET_ACCESS_KEY")
    if ((user_access_key_id != "") and (user_secret_access_key == "")) or (
        (user_access_key_id == "") and (user_secret_access_key != "")
    ):
        exit_error(
            "inputs IAM user Access Key ID and Secret Access Key always provided as a pair"
        )

    web_identity_role_arn = _env("INPUT_WEB_IDENTITY_ROLE_ARN")
    if (user_access_key_id != "") and (web_identity_role_arn != ""):
        exit_error(
            "only one of inputs IAM user Access Key ID/Secret Access Key pairs or OpenID Connect (OIDC) web identity role ARN to be provided"
        )

    if (user_access_key_id == "") and (web_identity_role_arn == ""):
        exit_error(
            "exactly one of inputs IAM user Access Key ID/Secret Access Key pairs or OpenID Connect (OIDC) web identity role ARN must be provided"
        )

    assume_role_arn = _env("INPUT_ASSUME_ROLE_ARN")
    if (user_access_key_id != "") and (assume_role_arn == ""):
        exit_error(
            "input IAM user Access Key ID/Secret Access Key pairs must be used with a target assume IAM role ARN"
        )

    assume_role_duration = _env("INPUT_ASSUME_ROLE_DURATION_SECONDS")
    if not assume_role_duration.isdigit():
        exit_error("input assume role duration seconds must be numeric")

    assume_role_session_name = _env("INPUT_ASSUME_ROLE_SESSION_NAME")
    if assume_role_session_name == "":
        exit_error("input assume role session name must be provided")

    aws_region = _env("INPUT_AWS_REGION")
    if aws_region == "":
        exit_error("input AWS region must be provided")

    return (
        user_access_key_id,
        user_secret_access_key,
        web_identity_role_arn,
        assume_role_arn,
        assume_role_duration,
        assume_role_session_name,
        aws_region,
    )


def fetch_oidc_jwt() -> str:
    # fetch GitHub environment variables to make HTTP token fetch request
    req_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    if req_url is None:
        exit_error(
            "expected ACTIONS_ID_TOKEN_REQUEST_URL environment variable not found"
        )

    req_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if req_token is None:
        exit_error(
            "expected ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not found"
        )

    # build HTTP request and execute
    request = urllib.request.Request(
        headers={"Authorization": "bearer " + req_token}, url=req_url
    )

    try:
        response = urllib.request.urlopen(request)
    except urllib.error.HTTPError as err:
        exit_error(
            "unexpected error fetching OIDC web identity token: " + str(err.read())
        )

    # parse response, return `value` property - containing the desired web identity JWT
    try:
        token_data = json.load(response)
    except json.decoder.JSONDecodeError:
        exit_error("unable to fetch OIDC web identity token - malformed HTTP response")

    response.close()
    return token_data.get("value", "")


def aws_sts_assume_role(
    cmd_name: str,
    role_arn: str,
    role_session_name: str,
    role_duration: str,
    web_identity_token: str = "",
    env_var_collection: Dict[str, str] = {},
) -> Tuple[str, str, str]:
    # build command argument list and environment variables to pass
    arg_list = [
        "aws",
        "sts",
        cmd_name,
        "--role-arn",
        role_arn,
        "--role-session-name",
        role_session_name,
        "--duration-seconds",
        role_duration,
    ]

    if web_identity_token != "":
        arg_list += ["--web-identity-token", web_identity_token]

    # set `AWS_EC2_METADATA_DISABLED` to avoid AWS CLI reaching out to metadata endpoint
    # on GitHub-hosted runners, which causes runtime error
    env_var_collection["AWS_EC2_METADATA_DISABLED"] = "true"
    env_var_collection["PATH"] = os.environ.get("PATH", "")

    # execute AWS CLI command
    try:
        result = subprocess.run(
            arg_list,
            encoding="utf-8",
            env=env_var_collection,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
    except FileNotFoundError as ex:
        exit_error("unable to assume role, AWS CLI installed?")

    if result.returncode != 0:
        exit_error("unable to assume role: \n" + result.stderr.strip())

    # parse JSON response from AWS CLI assume role call
    try:
        assume_data = json.loads(result.stdout)
    except json.decoder.JSONDecodeError:
        exit_error("unable to assume role - malformed AWS CLI response")

    # pull out generated session credentials
    def credential_part(key: str) -> str:
        if "Credentials" not in assume_data:
            return ""

        return assume_data["Credentials"].get(key, "")

    access_key_id = credential_part("AccessKeyId")
    secret_access_key = credential_part("SecretAccessKey")
    session_token = credential_part("SessionToken")
    if (access_key_id == "") or (secret_access_key == "") or (session_token == ""):
        exit_error("unable to assume role, missing expected response credentials")

    return (access_key_id, secret_access_key, session_token)


def write_aws_env_var_collection(
    env_export_file_path: str,
    access_key_id: str,
    secret_access_key: str,
    session_token: str,
    aws_region: str,
):
    # write AWS session credentials to GitHub environment file for job steps which follow
    fh = open(env_export_file_path, "w")
    fh.write(
        f"AWS_ACCESS_KEY_ID={access_key_id}\n"
        + f"AWS_SECRET_ACCESS_KEY={secret_access_key}\n"
        + f"AWS_SESSION_TOKEN={session_token}\n"
        + f"AWS_REGION={aws_region}\n"
    )

    fh.close()

    # mask any AWS session credential values from GitHub Actions logs if echoed in job steps which follow
    mask_value(access_key_id)
    mask_value(secret_access_key)
    mask_value(session_token)


def main():
    # read inputs passed to action
    (
        user_access_key_id,
        user_secret_access_key,
        web_identity_assume_role_arn,
        assume_role_arn,
        assume_role_duration,
        assume_role_session_name,
        aws_region,
    ) = read_inputs()

    # fetch and ensure GITHUB_ENV environment variable exists
    env_export_file_path = os.environ.get("GITHUB_ENV")
    if env_export_file_path is None:
        exit_error("expected GITHUB_ENV environment variable not found")

    if user_access_key_id != "":
        # using an IAM user with Access Key ID/Secret Access Key to assume a target IAM role ARN
        print("Assuming IAM role via IAM user")

        (access_key_id, secret_access_key, session_token) = aws_sts_assume_role(
            "assume-role",
            role_arn=assume_role_arn,
            role_session_name=assume_role_session_name,
            role_duration=assume_role_duration,
            env_var_collection={
                "AWS_ACCESS_KEY_ID": user_access_key_id,
                "AWS_SECRET_ACCESS_KEY": user_secret_access_key,
            },
        )

        write_aws_env_var_collection(
            env_export_file_path,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            aws_region=aws_region,
        )

    else:
        # using OpenID Connect (OIDC) to assume via web identity a target IAM role ARN
        # and then optionally assume *another* IAM role if `assume_role_arn` non-empty
        print("Assuming IAM role via OIDC")

        wi_token = fetch_oidc_jwt()
        (access_key_id, secret_access_key, session_token) = aws_sts_assume_role(
            "assume-role-with-web-identity",
            role_arn=web_identity_assume_role_arn,
            role_session_name=assume_role_session_name,
            role_duration=assume_role_duration,
            web_identity_token=wi_token,
        )

        if assume_role_arn != "":
            # from the OIDC IAM role, assume another final IAM role
            (access_key_id, secret_access_key, session_token) = aws_sts_assume_role(
                "assume-role",
                role_arn=assume_role_arn,
                role_session_name=assume_role_session_name,
                role_duration=assume_role_duration,
                env_var_collection={
                    "AWS_ACCESS_KEY_ID": access_key_id,
                    "AWS_SECRET_ACCESS_KEY": secret_access_key,
                    "AWS_SESSION_TOKEN": session_token,
                },
            )

        write_aws_env_var_collection(
            env_export_file_path,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            aws_region=aws_region,
        )


if __name__ == "__main__":
    main()
