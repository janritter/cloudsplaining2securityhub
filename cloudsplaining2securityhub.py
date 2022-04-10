import json
import logging
import boto3
import datetime
import hashlib
from argparse import ArgumentParser


def parse_cli():
    parser = ArgumentParser(
        description='Send Cloudsplaining findings to AWS Security Hub')
    parser.add_argument("--account-id", required=True,
                        help="ID of the AWS containing AWS Security Hub")
    parser.add_argument("--cloudsplaining-file", required=True,
                        help="Filename of the Cloudsplaining JSON finding file")
    return parser.parse_args()


def read_json(file_name):
    logger.debug("Reading JSON file: %s", file_name)
    with open(file_name, 'r') as f:
        return json.load(f)


def get_new_findings(old_findings, new_findings):
    changed_new_findings = []

    for new_finding in new_findings:
        found = False
        for old_finding in old_findings:
            if new_finding['Id'] == old_finding['Id']:
                found = True
                logger.debug("Old hash for finding id %s: %s",
                             old_finding['Id'], old_finding['ProductFields']['personal/default/Hash'])
                if new_finding['ProductFields']['personal/default/Hash'] != old_finding['ProductFields']['personal/default/Hash']:
                    logger.info("Finding for id %s changed, new hash: %s",
                                new_finding['Id'], new_finding['ProductFields']['personal/default/Hash'])
                    changed_new_findings.append(new_finding)
                else:
                    logger.info("Finding for id %s unchanged",
                                new_finding['Id'])

                break
        if not found:
            logger.info("New finding for id %s, hash: %s",
                        new_finding['Id'], new_finding['ProductFields']['personal/default/Hash'])
            changed_new_findings.append(new_finding)

    return changed_new_findings


def finding_payload_privilege_escalation(policy_name, resource_name, resource_type, methods, resources):
    remediation = {
        'Recommendation': {
            'Text': 'More information can be found here',
            'Url': 'https://cloudsplaining.readthedocs.io/en/latest/glossary/privilege-escalation/'
        }
    }
    return finding_payload(
        f'cloudsplaining-privilege-escalation-{policy_name}-{resource_name}',
        'cloudsplaining-privilege-escalation',
        f'Privilege escalation possible in IAM policy {policy_name} for {resource_type} {resource_name}',
        'This policy allows a combination of IAM actions that allow a principal with these permissions to escalate their privileges - Privilege Escalation Methods: ' + methods,
        resources,
        remediation
    )


def finding_payload(id, generator_id, title, description, resources, remediation=None):
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    hash_payload = {
        'SchemaVersion': '2018-10-08',
        'Id': id,
        'ProductArn': f'arn:aws:securityhub:eu-central-1:{aws_account_id}:product/{aws_account_id}/default',
        'GeneratorId': generator_id,
        'AwsAccountId': aws_account_id,
        'Title': title,
        'Description': description,
        'Resources': resources,
        'FindingProviderFields': {
            'Severity': {
                'Label': 'HIGH',
                'Original': 'HIGH'
            },
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE']
        },
        'Remediation': remediation,
    }

    hash = hashlib.sha256(str(hash_payload).encode())
    logger.info("Hash of finding payload: %s", hash.hexdigest())

    return {
        'SchemaVersion': '2018-10-08',
        'Id': id,
        'ProductArn': f'arn:aws:securityhub:eu-central-1:{aws_account_id}:product/{aws_account_id}/default',
        'GeneratorId': generator_id,
        'AwsAccountId': aws_account_id,
        'CreatedAt': timestamp,
        'UpdatedAt': timestamp,
        'Title': title,
        'Description': description,
        'Resources': resources,
        'FindingProviderFields': {
            'Severity': {
                'Label': 'HIGH',
                'Original': 'HIGH'
            },
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE']
        },
        'Remediation': remediation,
        'ProductFields': {
            'personal/default/Hash': hash.hexdigest(),
        }
    }


def combine_privilege_escalation_methods(privilege_escalations):
    methods = []
    for privilege_escalation in privilege_escalations:
        logger.debug(
            "Privilege escalation: %s",
            privilege_escalation
        )

        privilege_escalation_type = privilege_escalation['type']
        privilege_escalation_actions = privilege_escalation['actions']

        methods.append(
            privilege_escalation_type +
            ' (' + ', '.join(privilege_escalation_actions) + ')'
        )

    return ' / '.join(methods)

# User and policy


def get_finding_resource_for_user_policy(user_name, user_arn, policy_name):
    return [
        {
            'Type': 'AwsIamUser',
            'Id': user_arn,
            'Region': 'eu-central-1',
            'Details': {
                'AwsIamUser': {
                    'UserId': user_arn,
                    'UserName': user_name,
                    'UserPolicyList': [
                        {
                            'PolicyName': policy_name
                        }
                    ]
                }
            }
        }
    ]


def get_privilege_escalation_finding_for_user_policy(policies, user_policies, user_name, user_arn):
    findings = []

    for policy_id in user_policies:
        policy = policies[policy_id]
        policy_name = policy['PolicyName']
        logger.debug("Policy: %s", policy)

        privilege_escalations = policy['PrivilegeEscalation']
        if len(privilege_escalations) > 0:
            logger.info("Found privilege escalation in inline policy with name %s for user %s",
                        policy_name, id)

            finding = finding_payload_privilege_escalation(
                policy_name,
                user_name,
                "IAM User",
                combine_privilege_escalation_methods(privilege_escalations),
                get_finding_resource_for_user_policy(
                    user_name, user_arn, policy_name)
            )

            logger.debug("Finding: %s", finding)
            findings.append(finding)

    return findings


# Role and Policy

def get_finding_resource_for_role_policy(role_name, role_id, policy_name):
    return [
        {
            'Type': 'AwsIamRole',
            'RoleId': role_id,
            'RoleName': role_name,
            'Region': 'eu-central-1',
            'RolePolicyList': [
                {
                    'PolicyName': policy_name
                }
            ]
        }
    ]


def get_privilege_escalation_finding_for_role_policy(policies, role_policies, role_name, role_id):
    findings = []

    for policy_id in role_policies:
        policy = policies[policy_id]
        policy_name = policy['PolicyName']
        logger.debug("Policy: %s", policy)

        privilege_escalations = policy['PrivilegeEscalation']
        if len(privilege_escalations) > 0:
            logger.info("Found privilege escalation in inline policy with name %s for role %s",
                        policy_name, id)

            finding = finding_payload_privilege_escalation(
                policy_name,
                user_name,
                "IAM Role",
                combine_privilege_escalation_methods(privilege_escalations),
                get_finding_resource_for_role_policy(
                    role_name, role_id, policy_name
                )
            )

            logger.debug("Finding: %s", finding)
            findings.append(finding)

    return findings


# Logging
logger = logging.getLogger('cloudsplaining2securityhub')
logger.setLevel(logging.DEBUG)

# console logging
ch = logging.StreamHandler()

# create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)
logger.addHandler(ch)


args = parse_cli()
aws_account_id = args.account_id
cloudsplaining_file = args.cloudsplaining_file

client = boto3.client('securityhub')

findings = read_json(cloudsplaining_file)

users = findings['users']
roles = findings['roles']
inline_policies = findings['inline_policies']
customer_managed_policies = findings['customer_managed_policies']

findings = []

logger.info('Iterating through users')
for id, user in users.items():
    user_arn = user['arn']
    user_name = user['name']

    logger.info("Getting inline_plicy findings for user %s", id)
    findings += get_privilege_escalation_finding_for_user_policy(
        inline_policies, user['inline_policies'], user_name, user_arn
    )

    logger.info("Getting customer_managed_plicy findings for user %s", id)
    findings += get_privilege_escalation_finding_for_user_policy(
        customer_managed_policies, user['customer_managed_policies'], user_name, user_arn
    )

logger.info('Iterating through roles')
for id, role in roles.items():
    role_id = role['id']
    role_name = role['name']

    logger.info("Getting inline_plicy findings for role %s", id)
    findings += get_privilege_escalation_finding_for_role_policy(
        inline_policies, role['inline_policies'], role_name, role_id
    )

    logger.info("Getting customer_managed_plicy findings for role %s", id)
    findings += get_privilege_escalation_finding_for_role_policy(
        customer_managed_policies, role['customer_managed_policies'], role_name, role_id
    )


response = client.get_findings(
    Filters={
        'ProductArn': [
            {
                'Value': f'arn:aws:securityhub:eu-central-1:{aws_account_id}:product/{aws_account_id}/default',
                'Comparison': 'EQUALS'
            },
        ],
    }
)

old_findings = response['Findings']

changed_new_findings = get_new_findings(old_findings, findings)

if len(changed_new_findings) > 0:
    logger.info("Found %s new / changed findings", len(changed_new_findings))

    response = client.batch_import_findings(
        Findings=changed_new_findings
    )

    logger.debug("Batch import findings response: %s", response)
