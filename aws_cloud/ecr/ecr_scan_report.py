#!/usr/bin/env python3

"""
The script to scan and reporting docker vulnerabilities stored in ECR.
"""

import datetime

# pylint: disable=broad-except,invalid-name,too-many-branches
import json
import logging
import sys
import tempfile
import time
from datetime import datetime, timezone
from math import floor

import boto3
import click
from botocore.config import Config
from botocore.exceptions import ParamValidationError
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.WARNING)
logger = logging.getLogger("monitoring")


def get_boto_client(ctx, aws_service="ecr"):
    """
    Get Boto client
    """
    logger.info("Get client, region: %s, service: %s ", ctx["region"], aws_service)
    boto_config = Config(
        region_name=ctx["region"],
        signature_version="v4",
        retries={"max_attempts": 10, "mode": "standard"},
    )
    try:
        client = boto3.client(aws_service, config=boto_config)
        return client
    except ParamValidationError as err:
        logger.error("The parameters you provided are incorrect: %s", err)
        raise err


def get_account_id(ctx):
    """
    Retrieves the accountID
    """
    try:
        sts_client = get_boto_client(ctx, "sts")
        account = sts_client.get_caller_identity()["Account"]
        return account
    except ParamValidationError as err:
        logger.error("The parameters you provided are incorrect: %s", err)
        raise err


def get_repos_from_ecr(ecr_client, account_id: str):
    """
    Gets a dict of repos from the ECR
    """
    try:
        repo_s = ecr_client.describe_repositories(
            registryId=account_id, maxResults=1000
        )
        logger.info(
            "AccountID: %s, Repositories found: %s ",
            str(account_id),
            len(repo_s["repositories"]),
        )
    except ParamValidationError as err:
        logger.error(
            "The parameters you provided for describe repositories are incorrect: %s",
            err,
        )
        sys.exit(1)
    return repo_s


def fun_for_sort_at(element):
    """
    Sort function by PushedAt
    """
    return int(element.get("PushedAt", "0"))


def fun_for_sort_tag(element):
    """
    Sort function by Tag
    """
    return element.get("Tag", 0)


def get_sorted_images(ctx, ecr_images):
    """
    Function for Getting sorted images
    """
    list_for_sort = []
    for image in ecr_images["imageDetails"]:
        timeimage = image["imagePushedAt"]
        imageage = ctx["timenow"] - timeimage
        image_pushed_at_days = int(floor(imageage.total_seconds() / 60 / 60))
        digest_list = [
            {
                "Digest": str(image["imageDigest"]),
                "Tag": image.get(["imageTags"][0]),
                "PushedAt": image_pushed_at_days,
            }
        ]
        list_for_sort.extend(digest_list)
    if list_for_sort and ctx["tags_all"]:
        list_for_sort.sort(key=fun_for_sort_tag, reverse=True)
        logger.debug("List of images: %s", list_for_sort)
        return list_for_sort
    if list_for_sort:
        list_for_sort.sort(key=fun_for_sort_at)
        return list_for_sort[0]
    return False


def get_images_from_repo(ctx, ecr_client, repo_obj):
    """
    Gets a dict of images from a repo
    """
    try:
        ecr_images = ecr_client.describe_images(
            registryId=ctx["account"],
            repositoryName=str(repo_obj["repositoryName"]),
            maxResults=1000,
        )
        logger.info(
            "Repo: %s, Images found: %s ",
            repo_obj["repositoryName"],
            str(len(ecr_images["imageDetails"])),
        )
        limages = get_sorted_images(ctx, ecr_images)
        if limages and ctx["tags_all"]:
            images = {"imageDetails": []}
            for image in limages:
                resp = ecr_client.describe_images(
                    registryId=ctx["account"],
                    repositoryName=str(repo_obj["repositoryName"]),
                    imageIds=[
                        {"imageDigest": image["Digest"]},
                    ],
                )
                images["imageDetails"].extend(resp["imageDetails"])
            return images["imageDetails"]
        if limages:
            resp = ecr_client.describe_images(
                registryId=ctx["account"],
                repositoryName=str(repo_obj["repositoryName"]),
                imageIds=[
                    {"imageDigest": limages["Digest"]},
                ],
            )
            return resp["imageDetails"]

    except ParamValidationError as err:
        logger.error(
            "Repo: { %s, %s, }, Error describe images", repo_obj["repositoryName"], err
        )
    return False


def get_image_age(ctx, img_obj):
    """
    Gets the image age of a given img_obj and returns as hours
    """
    try:
        timeimage = img_obj["imagePushedAt"]
        imageage = ctx["timenow"] - timeimage
        return int(floor(imageage.total_seconds() / 60 / 60))
    except KeyError as err:
        logger.error("%s", err)
    return -1


def get_scan_age(ctx, img_obj):
    """
    Gets the age of the last scan (if scanned at all)
    and returns as hours (-1 for error or never scanned)
    """
    try:
        if img_obj.get("imageScanFindingsSummary"):
            timeimage = img_obj["imageScanFindingsSummary"]["imageScanCompletedAt"]
            imageage = ctx["timenow"] - timeimage
            return int(floor(imageage.total_seconds() / 60 / 60))
    except KeyError as err:
        logger.error("Error: %s", err)
    return -1


def scan_report_it_or_not(ctx, img_obj):
    """
    Determine if an image provided as img_obj shall be scanned or reported based on the context.
    """
    image_age = get_image_age(ctx, img_obj)
    scan_age = get_scan_age(ctx, img_obj)
    image_digest = img_obj["imageDigest"][-5:]
    message = (
        f"ImageDigestLast5: {image_digest}, ImageAge: {image_age}, ScanAge: {scan_age}"
    )

    try:
        if scan_age == -1:
            if (
                "imageScanStatus" in img_obj
                and img_obj["imageScanStatus"]["status"] == "FAILED"
            ):
                logger.info(
                    "%s - Image not supported for scanning, skip for scan and report.",
                    message,
                )
                return False
            logger.info("%s - never scanned, scan it, check for reporting.", message)
            return True

        if scan_age > ctx["imageage"]:
            log_message = (
                "scan older than specified min age, check for reporting."
                if ctx["job"] == "report"
                else "Scan age too old, schedule scan.."
            )
            logger.info("%s - %s", message, log_message)
            return True

        if scan_age <= ctx["imageage"]:
            log_message = (
                "scan newer than specified min age, check for reporting."
                if ctx["job"] == "report"
                else "Scan age too fresh, skip scan."
            )
            logger.info("%s - %s", message, log_message)
            return ctx["job"] == "report"

        if image_age > ctx["imageage"]:
            logger.info("%s - don't process, image too old.", message)
            return False

    except KeyError as err:
        logger.error("%s, Err: %s - skip in general.", message, str(err))
        return False

    logger.info(
        "%s - no idea why this fell through the mesh, please check the code..", message
    )
    return False


def image_scan(ecr_client, img_obj):
    """
    start image scan, fire and forget
    """
    image_digest = img_obj["imageDigest"][-5:]
    response = None
    if img_obj["imageTags"]:
        try:
            response = ecr_client.start_image_scan(
                registryId=img_obj["registryId"],
                repositoryName=str(img_obj["repositoryName"]),
                imageId={
                    "imageDigest": str(img_obj["imageDigest"]),
                    "imageTag": str(img_obj["imageTags"][0]),
                },
            )
            logger.info(
                "Repo: %s, ImgDigLast5: %s, Status: %s Scan successfully started..",
                img_obj["repositoryName"],
                image_digest,
                response["imageScanStatus"]["status"],
            )
        except ParamValidationError as err:
            logger.error(
                "Repo: %s, ImgDigLast5: %s, Error: %s Resp starting scan: %s ",
                img_obj["repositoryName"],
                image_digest,
                str(err),
                response,
            )
            return str(err)
        while 1:
            check = ecr_client.describe_images(
                registryId=img_obj["registryId"],
                repositoryName=str(img_obj["repositoryName"]),
                imageIds=[
                    {
                        "imageDigest": img_obj["imageDigest"],
                        "imageTag": img_obj["imageTags"][0],
                    },
                ],
            )
            if (
                str(check["imageDetails"][0]["imageScanStatus"]["status"])
                == "IN_PROGRESS"
            ):
                print(".", end="")
                time.sleep(1)
            else:
                print("done")
                return check
    return True


def get_scan_result(ctx, ecr_client, img_obj):
    """
    Gets the results of a scan for further processing
    """
    message = (
        f'Repo: {img_obj["repositoryName"]}, ImgDigLast5: {img_obj["imageDigest"][-5:]}'
    )
    imageUri = (
        f'{ctx["account"]}.dkr.ecr.{ctx["region"]}.amazonaws.com/'
        f'{img_obj["repositoryName"]}:{img_obj["imageTags"][0]}'
    )
    reportUri = (
        f'https://{ctx["region"]}.console.aws.amazon.com/ecr/repositories/private/{ctx["account"]}'
        f'/{img_obj["repositoryName"]}/image/{str(img_obj["imageDigest"])}/scan-results/'
    )
    try:
        details = ecr_client.describe_image_scan_findings(
            registryId=img_obj["registryId"],
            repositoryName=str(img_obj["repositoryName"]),
            imageId={
                "imageDigest": str(img_obj["imageDigest"]),
                "imageTag": str(img_obj["imageTags"][0]),
            },
        )
        imageScanStatus = str(details["imageScanStatus"]["status"])
        if imageScanStatus == "FAILED":
            resultJSON = json.dumps(
                {
                    "Account": ctx["account"],
                    "Repository": str(img_obj["repositoryName"]),
                    "Manifest": str(img_obj["imageDigest"]),
                    "Tag": imageUri.split(":")[1],
                    "ImageUri": imageUri,
                    "Report": reportUri,
                    "Summary": {"Exception": "Image not supported for scanning"},
                }
            )
            logger.error("%s - Report: Image not supported for scanning", message)
            return resultJSON
        if imageScanStatus != "FAILED":
            findings = []
            high = 0
            for finding in details["imageScanFindings"]["findings"]:
                logger.debug("Finding: %s", json.dumps(finding))
                if str(finding["severity"]) == "CRITICAL":
                    obj = {
                        "Name": finding["name"],
                        "Description": finding.get(["description"][0]),
                        "Uri": finding["uri"],
                        "Severity": finding["severity"],
                    }
                    findings.append(obj)
                if str(finding["severity"]) == "HIGH" and high <= 3:
                    high += 1
                    obj = {
                        "Name": finding["name"],
                        "Description": finding.get(["description"][0]),
                        "Uri": finding["uri"],
                        "Severity": finding["severity"],
                    }
                    findings.append(obj)
            logger.info("%s, - Report: Findings found.", len(findings))
            resultJSON = json.dumps(
                {
                    "Account": ctx["account"],
                    "Repository": str(img_obj["repositoryName"]),
                    "Manifest": str(img_obj["imageDigest"]),
                    "Tag": imageUri.split(":")[1],
                    "ImageUri": imageUri,
                    "Report": reportUri,
                    "Summary": img_obj["imageScanFindingsSummary"][
                        "findingSeverityCounts"
                    ],
                    "Vulnerabilities": findings,
                }
            )
            logger.debug("%s, - Report: findings added.", resultJSON)
            return resultJSON
    except ParamValidationError as err:
        logger.error("%s, Image not supported for scanning! ", str(err))
        errSummary = (
            "Image not supported for scanning! (Either too old or too new,"
            "check supported image versions:"
            "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
        )
        resultJSON = json.dumps(
            {
                "Account": ctx["account"],
                "Repository": str(img_obj["repositoryName"]),
                "Manifest": str(img_obj["imageDigest"]),
                "Tag": imageUri.split(":")[1],
                "ImageUri": imageUri,
                "Report": reportUri,
                "Summary": errSummary,
            }
        )
        return resultJSON
    return False


# pylint: disable=too-many-locals,too-many-statements
def report(ctx, ecr_client, image, scanReport):
    """
    Generate report
    """
    images = critical = high = medium = notsupported = 0

    timenowstring = str(ctx["timenow"].strftime("%Y-%m-%d-%H:%M:%S"))
    registryurl = f'https://{str(ctx["account"])}.dkr.ecr.{ctx["region"]}.amazonaws.com'

    try:
        scanResult = get_scan_result(ctx, ecr_client, image)
        if scanResult:
            scanReport["imageScanFindingsSummary"].append(json.loads(scanResult))
    except KeyError as err:
        logger.error("Error getting scan result: %s", str(err))

    if ctx["bucket"]:
        reportpath = (
            f's3://{ctx["bucket"]}'
            f"/regular-ecr-image-scanning-report-{timenowstring}.json"
        )
        logger.info("Filing report to: %s", reportpath)
        try:
            s3Client = get_boto_client(ctx, "s3")
            response = s3Client.upload_file(
                ctx["tmp_file"],
                ctx["bucket"],
                f"regular-ecr-image-scanning-report-{timenowstring}.json",
            )
            logger.info("S3 Upload resp: %s", response)
        except ParamValidationError as err:
            logging.error("Error uploading report: %s", err)

    for imageScanFinding in scanReport["imageScanFindingsSummary"]:
        images += 1
        try:
            critical += int(imageScanFinding["Summary"]["critical"])
        except KeyError:
            critical += 0
        try:
            high += int(imageScanFinding["Summary"]["high"])
        except KeyError:
            high += 0
        try:
            medium += int(imageScanFinding["Summary"]["medium"])
        except KeyError:
            medium += 0
        try:
            if (
                str(imageScanFinding["Summary"]["Exception"])
                == "Image not supported for scanning"
            ):
                notsupported += 1
        except Exception as err:
            notsupported += 0
            logging.debug("ERROR! %s", str(err))

    if len(scanReport["imageScanFindingsSummary"]) == 0:
        message = "No image scan finding to report."
        logger.info("Summary: %s", message)
    else:
        message = (
            f"\nEcr scanning summary {timenowstring} for registry {registryurl}:\n"
            f"critical: {str(critical)}, high: {str(high)}, medium: {str(medium)}"
            f" - findings total in {str(images)} images.\n"
            f"Detailed report: {reportpath}"
            if ctx["bucket"]
            else ""
        )
        logger.debug("Summary: %s", message)

    if ctx["snstopicarn"]:
        logger.info("Sending summary to SNS Topic Arn: %s", ctx["snstopicarn"])
        snsClient = get_boto_client(ctx, "sns")
        try:
            response = snsClient.publish(
                TopicArn=ctx["snstopicarn"],
                Message=message,
                Subject="ECR image scanning report",
            )
            logger.info("Resp to try to publishing to SNS: %s", str(response))
        except ParamValidationError as err:
            logger.error("Publishing to SNS: %s", str(err))
    return scanReport


# pylint: disable=too-many-nested-blocks
def scan_or_report(ctx, repos, ecr_client):
    """
    Function for scan or report
    """
    if repos is not False:
        ctx["tmp_file"] = tempfile.NamedTemporaryFile(
            mode="+r", delete=False, suffix=".json"
        ).name
        image_count = scan_count = repo_count = 0
        scanReport = {
            "ECRScanResult": str(ctx["timenow"]),
            "imageScanFindingsSummary": [],
        }
        for repo in repos["repositories"]:
            if not str(repo["repositoryName"]) in ctx["exclude"]:
                images = get_images_from_repo(ctx, ecr_client, repo)
                if images:
                    image_count += len(images)
                else:
                    continue
                repo_count += 1
                for image in images:
                    scan_report_decision = scan_report_it_or_not(ctx, image)
                    if scan_report_decision:
                        if str(repo["repositoryName"]) == ctx["reponame"]:
                            if ctx["job"] == "scan":
                                scanResult = image_scan(ecr_client, image)
                                try:
                                    if scanResult["imageDetails"][0]["imageScanStatus"][
                                        "description"
                                    ]:
                                        scan_count += 1
                                except KeyError:
                                    continue
                            if ctx["job"] == "report":
                                report_result = report(
                                    ctx, ecr_client, image, scanReport
                                )
                                scanReport.update(report_result)

                        if ctx["reponame"] == "*":
                            if ctx["job"] == "scan":
                                scanResult = image_scan(ecr_client, image)
                                try:
                                    if scanResult["imageDetails"][0]["imageScanStatus"][
                                        "description"
                                    ]:
                                        scan_count += 1
                                except KeyError:
                                    continue
                            if ctx["job"] == "report":
                                scanReport = report(ctx, ecr_client, image, scanReport)
                                continue
        logger.info(
            "Finished %s: %s, images: %s, repo: %s, scans in total..",
            ctx["job"],
            scan_count,
            image_count,
            repo_count,
        )

        return scanReport["imageScanFindingsSummary"]
    return None


def report_to_slack(ctx, findings_summary):
    """
    Prepare and publish message to the slack channel
    """

    slack_client = WebClient(token=ctx["slacktoken"])
    message = ""
    for item in findings_summary:
        message += f'<{item["Report"]}|{item["Repository"]}:{item["Tag"]}> \
`{json.dumps(item["Summary"])}`\n'
    logger.debug("Message: %s", message)

    try:
        response = slack_client.chat_postMessage(
            channel=ctx["slackchannel"], text=message
        )
        logger.debug("Response from slack API: %s", response["message"]["text"])
        assert response["message"]["text"] == message
        return response["ok"]
    except SlackApiError as e:
        assert e.response["ok"] is False
        assert e.response["error"]
        logger.error("Got an error: %s", e.response["error"])
    return None


# pylint: disable=too-many-arguments
@click.command(
    context_settings=dict(
        ignore_unknown_options=True, help_option_names=["-h", "--help"]
    )
)
@click.option(
    "-a",
    "--account",
    show_default=True,
    envvar="AWS_ACCOUNT_ID",
    help="AWS_ACCOUNT_ID(AWS_ACCOUNT_ID) can be passed via env",
    default="*",
)
@click.option(
    "-r",
    "--region",
    show_default=True,
    envvar="AWS_REGION",
    help="AWS_REGION(AWS_REGION) can be passed via env",
    default="us-east-1",
)
@click.option(
    "-n",
    "--reponame",
    show_default=True,
    help="specifies a repository name .. defaults to '*', meaning scan all",
    default="*",
)
@click.option(
    "-e",
    "--exclude",
    show_default=True,
    help="Specify repository/s in order to ignore actions on them: -e '[repo1,repo2,...]'",
    default=[],
)
@click.option(
    "-o",
    "--snstopicarn",
    show_default=True,
    help="SNS topic arn to scan summary to.",
    default=False,
)
@click.option(
    "-s",
    "--slacktoken",
    show_default=True,
    envvar="SLACK_TOKEN",
    help="Slack token to send summary to the slack cannel.",
    default=False,
)
@click.option(
    "-c",
    "--slackchannel",
    show_default=True,
    envvar="SLACK_CHANNEL",
    help="Slack token to send summary to the slack channel.",
    default="random",
)
@click.option(
    "-b",
    "--bucket",
    show_default=True,
    help="S3 bucket to place reports in json format to.",
    default=False,
)
@click.option(
    "-m",
    "--imageage",
    type=int,
    show_default=True,
    help="The age of an image (h) to considered to be too old for scanning",
    default="48",
)
@click.option(
    "-j",
    "--job",
    show_default=True,
    type=click.Choice(["scan", "report"]),
    help="The job should be performed possible can be `report` or `scan`",
    default="scan",
)
@click.option(
    "-l",
    "--log_level",
    default="INFO",
    envvar="LOGLEVEL",
    show_default=True,
    help="The logging level can be configured via `LOGLEVEL` variable over env",
)
@click.option(
    "--tags_all/--tag_latest",
    default=False,
    show_default=True,
    help="Perform action on all tags are published within repository",
)
@click.help_option("-h", "--help")
def main(
    account: str,
    region: str,
    reponame: str,
    exclude: list,
    snstopicarn: str,
    slacktoken: str,
    slackchannel: str,
    imageage: int,
    job: str,
    log_level: str,
    tags_all: bool,
    bucket: str,
):
    """
    Main function, to manage scan on vulnerability of images and generate report of findings
    """
    logger.setLevel(log_level)
    ctx = {}
    ctx["account"] = account
    ctx["region"] = region
    ctx["reponame"] = reponame
    ctx["exclude"] = exclude
    ctx["snstopicarn"] = snstopicarn
    ctx["slacktoken"] = slacktoken
    ctx["slackchannel"] = slackchannel
    ctx["imageage"] = imageage
    ctx["job"] = job
    ctx["log_level"] = log_level
    ctx["tags_all"] = tags_all
    ctx["bucket"] = bucket
    ctx["timenow"] = datetime.now(timezone.utc)

    logger.info("Initializing %s..", job)
    ecr_client = get_boto_client(ctx, "ecr")
    if ecr_client is False:
        logger.error("Authentication failure, exiting..")
        sys.exit(1)
    else:
        logger.info("Authentication succeeded..")
        if ctx["account"] == "*":
            account_id = get_account_id(ctx)
            ctx["account"] = account_id
    repos = get_repos_from_ecr(ecr_client, ctx["account"])
    scan_summary = scan_or_report(ctx, repos, ecr_client)
    if ctx["job"] == "report" and scan_summary:
        with open(ctx["tmp_file"], "w", encoding="utf-8") as f:
            json.dump(scan_summary, f, ensure_ascii=False, indent=4)
        logger.info("The scan report has been stored in to: %s", str(ctx["tmp_file"]))
    if slacktoken and scan_summary:
        responce = report_to_slack(ctx, scan_summary)
        if responce:
            logger.info(
                "The Slack message has been published to the %s channel successfully..",
                slackchannel,
            )

    sys.exit(0)


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter # click limitation
    main()
