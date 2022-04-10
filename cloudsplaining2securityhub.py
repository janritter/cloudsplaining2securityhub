import json
import logging
import boto3
import datetime
import hashlib
from argparse import ArgumentParser
from string import Template

enabled_cloudsplaining_findings = [
    'PrivilegeEscalation',
    'ResourceExposure',
]

security_hub_finding_presets = {
    'PrivilegeEscalation': {
        'finding_id': Template('cloudsplaining-privilege-escalation-$policy_name-$resource_name'),
        'generator_id': 'cloudsplaining-privilege-escalation',
        'title': Template('Privilege escalation possible in IAM policy $policy_name for $resource_type $resource_name'),
        'description': Template('This policy allows a combination of IAM actions that allow a principal with these permissions to escalate their privileges - Privilege Escalation Methods: $actions'),
        'severity': 'HIGH',
        'remediation': {
            'Recommendation': {
                'Text': 'More information can be found here',
                'Url': 'https://cloudsplaining.readthedocs.io/en/latest/glossary/privilege-escalation/'
            }
        }
    },
    'ResourceExposure': {
        'finding_id': Template('cloudsplaining-resource_exposure-$policy_name-$resource_name'),
        'generator_id': 'cloudsplaining-resource-exposure',
        'title': Template('Resource exposure possible in IAM policy $policy_name for $resource_type $resource_name'),
        'description': Template('This policy allows actions that permit modification of resource-based policies or can otherwise can expose AWS resources to the public via similar actions that can lead to resource exposure - Actions: $actions'),
        'severity': 'MEDIUM',
        'remediation': {}
    }
}


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


def get_new_changed_findings(old_findings, new_findings):
    changed_new_findings = []

    for new_finding in new_findings:
        found = False
        for old_finding in old_findings:
            if new_finding['Id'] == old_finding['Id']:
                found = True
                logger.debug(
                    "Old hash for finding id %s: %s",
                    old_finding['Id'],
                    old_finding['ProductFields']['personal/default/Hash']
                )
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


def finding_payload(cloudsplaining_finding_type, actions, policy_name, resource):
    title = security_hub_finding_presets[cloudsplaining_finding_type]['title'].substitute(
        {
            'policy_name': policy_name,
            'resource_name': resource['name'],
            'resource_type': 'IAM User' if resource['type'] == 'IAMUser' else 'IAM Role'
        }
    )
    finding_id = security_hub_finding_presets[cloudsplaining_finding_type]['finding_id'].substitute(
        {
            'policy_name': policy_name,
            'resource_name': resource['name']
        }
    )
    description = security_hub_finding_presets[cloudsplaining_finding_type]['description'].substitute(
        {
            'actions': combine_privilege_escalation_methods(actions) if cloudsplaining_finding_type == 'PrivilegeEscalation' else '(' + ', '.join(actions) + ')'
        }
    )

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    resource = get_finding_resource(resource, policy_name)

    hash_payload = {
        'SchemaVersion': '2018-10-08',
        'Id': finding_id,
        'ProductArn': f'arn:aws:securityhub:eu-central-1:{aws_account_id}:product/{aws_account_id}/default',
        'GeneratorId': security_hub_finding_presets[cloudsplaining_finding_type]['generator_id'],
        'AwsAccountId': aws_account_id,
        'Title': title,
        'Description': description,
        'Resources': resource,
        'FindingProviderFields': {
            'Severity': {
                'Label': security_hub_finding_presets[cloudsplaining_finding_type]['severity'],
                'Original': security_hub_finding_presets[cloudsplaining_finding_type]['severity'],
            },
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE']
        },
        'Remediation': security_hub_finding_presets[cloudsplaining_finding_type]['remediation'],
    }

    hash = hashlib.sha256(str(hash_payload).encode())
    logger.info("Hash of finding payload: %s", hash.hexdigest())

    return {
        'SchemaVersion': '2018-10-08',
        'Id': finding_id,
        'ProductArn': f'arn:aws:securityhub:eu-central-1:{aws_account_id}:product/{aws_account_id}/default',
        'GeneratorId': security_hub_finding_presets[cloudsplaining_finding_type]['generator_id'],
        'AwsAccountId': aws_account_id,
        'CreatedAt': timestamp,
        'UpdatedAt': timestamp,
        'Title': title,
        'Description': description,
        'Resources': resource,
        'FindingProviderFields': {
            'Severity': {
                'Label': security_hub_finding_presets[cloudsplaining_finding_type]['severity'],
                'Original': security_hub_finding_presets[cloudsplaining_finding_type]['severity'],
            },
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE']
        },
        'Remediation': security_hub_finding_presets[cloudsplaining_finding_type]['remediation'],
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

# Generic


def get_finding_resource(resource, policy_name):
    if resource['type'] == 'IAMUser':
        return [
            {
                'Type': 'AwsIamUser',
                'Id': resource['arn'],
                'Region': 'eu-central-1',
                'Details': {
                    'AwsIamUser': {
                        'UserId': resource['arn'],
                        'UserName': resource['name'],
                        'UserPolicyList': [
                            {
                                'PolicyName': policy_name
                            }
                        ]
                    }
                }
            }
        ]
    if resource['type'] == "IAMRole":
        return [
            {
                'Type': 'AwsIamRole',
                'Id': resource['id'],
                'Region': 'eu-central-1',
                'Details': {
                    'AwsIamRole': {
                        'RoleId': resource['id'],
                        'RoleName': resource['name'],
                        'RolePolicyList': [
                            {
                                'PolicyName': policy_name
                            }
                        ]
                    }
                }
            }
        ]

def get_all_findings_for_resource(policies, resource_policies, resource):
    findings = []

    resource_name = resource['name']

    for policy_id in resource_policies:
        policy = policies[policy_id]
        policy_name = policy['PolicyName']
        logger.debug("Policy with name %s: %s", policy_name, policy)

        for cloudsplaining_finding_type in enabled_cloudsplaining_findings:
            problems = policy[cloudsplaining_finding_type]

            if len(problems) > 0:
                logger.info("Found %s in policy with name %s for resource %s",
                            cloudsplaining_finding_type, policy_name, resource_name)

                finding = finding_payload(
                    cloudsplaining_finding_type,
                    problems,
                    policy_name,
                    resource
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
    resource = {
        'arn': user['arn'],
        'name':  user['name'],
        'type': 'IAMUser'
    }

    user_policies = user['inline_policies']
    logger.debug("User inline_policies: %s", user_policies)

    logger.info("Checking inline_policy for user %s", id)
    findings.extend(get_all_findings_for_resource(
        inline_policies, user_policies, resource))

    user_policies = user['customer_managed_policies']
    logger.debug("User customer_managed_policies: %s", user_policies)

    logger.info("Checking customer_managed_policy for user %s", id)
    findings.extend(get_all_findings_for_resource(
        customer_managed_policies, user_policies, resource))

for id, role in roles.items():
    resource = {
        'id': role['id'],
        'name': role['name'],
        'type': 'IAMRole'
    }

    role_policies = role['inline_policies']
    logger.debug("Role inline_policies: %s", role_policies)

    logger.info("Checking inline_policy for role %s", id)
    findings.extend(get_all_findings_for_resource(
        inline_policies, role_policies, resource))

    role_policies = role['customer_managed_policies']
    logger.debug("Role customer_managed_policies: %s", role_policies)

    logger.info("Checking customer_managed_policy for role %s", id)
    findings.extend(get_all_findings_for_resource(
        customer_managed_policies, role_policies, resource))


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

changed_new_findings = get_new_changed_findings(old_findings, findings)

if len(changed_new_findings) > 0:
    logger.info("Found %s new / changed findings", len(changed_new_findings))

    response = client.batch_import_findings(
        Findings=changed_new_findings
    )

    logger.debug("Batch import findings response: %s", response)
