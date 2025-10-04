# DetentionDodger: Finding rusted links on the chains of fate

## Description
AWSCompromisedKeyQuarantineV2 (v3 was released during the creation of this article) is an AWS policy that attaches to identities whose credentials are leaked. It denies access to certain actions, applied by the AWS team in the event that an IAM user's credentials have been compromised or exposed publicly. AWS recently modified their public documentation to include the following:

While it is not the intended use of the policy, many see it as the first line of defense for an exposed access key. In fact, we have observed several organizations preemptively assign this policy to sensitive identities to limit actions that can occur.

DetentionDodger was built as a tool to automate the process of enumerating the account for users with leaked credentials and finding out their privileges and the impact they will have on the account.

## Code
https://github.com/Permiso-io-tools/DetentionDodger
