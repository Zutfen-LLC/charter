# Working on Charter

Use the issue number to scope each change. Put new behavior on a branch and open a focused pull request with the issue, tests run and results, and any limitations. Use synthetic fixtures so another contributor can reproduce the work without a cloud account or credentials.

For changes to identity, routing, retention, or export, state the trust boundaries and include a negative-path test. Keep credentials, private endpoints, actual client or matter information, and non-synthetic evidence out of commits, issues, and CI artifacts. Do not report suspected vulnerabilities or credentials in public issues.

Do not copy ZCode sources, binaries or bundled assets into this repository until the upstream and distribution review is complete. The upstream license does not by itself select a license for Charter; resolve that decision before inviting external code contributions.
