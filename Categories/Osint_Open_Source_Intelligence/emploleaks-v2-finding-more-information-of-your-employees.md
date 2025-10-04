# Emploleaks v2: Finding [more] Information of your Employees

## Description
During red team assessments, our team found that personal information leaked in breaches can be a significant risk to our clients. It is often the case that personal passwords are reused in enterprise environments. But even when they don't, these passwords in conjunction with other personal information can be used to derive working credentials for employer resources.

Collecting this information manually is a tedious process, so we developed a tool that helped us quickly identify any leaked employee information associated with our clients.

The tool proved to be incredibly useful for our team while it was used internally. Still, we recognized the potential benefits it could offer to other organizations facing similar security challenges. Therefore, we made the decision to open-source the tool.

Our security tool enables the collection of personal information through Open Source Intelligence techniques. It begins by taking a company domain and retrieving a list of employees from LinkedIn. It then gathers data on individuals across various social media platforms, such as Twitter, LinkedIn, GitHub, GitLab, and more, with the goal of obtaining personal email addresses. Once these email addresses are found, the tool searches through the COMB database and other internet sources to check if the user's password has been exposed in any leaks.

We believe that by making this tool openly available, we can help organizations proactively identify and mitigate the risk associated with leaked employee credentials, ultimately contributing to a more secure digital ecosystem for everyone.

## Code
https://github.com/Base4Security/DOLOS-T
