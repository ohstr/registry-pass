# Examples

Ways to run a registry where a community hosts its agents. Each folder has a
`grants.yaml` you can point `grants.file` at, and the client commands.

| Example | What it shows |
|---|---|
| [community-agents](community-agents/) | Members publish agents under their own name; anyone pulls them |
| [membership](membership/) | Add a member, change their key, remove them |
| [ci-publishing](ci-publishing/) | Publish an agent image from GitHub Actions with a Nostr key |
| [verified-catalog](verified-catalog/) | A curated `verified/` namespace only a curator can push to |
| [team-agents](team-agents/) | A private namespace shared by a team |
| [runtime-nodes](runtime-nodes/) | Servers and Kubernetes nodes that run agents and only pull |
| [agent-identity](agent-identity/) | An agent with its own key publishing its results |
| [storage-quota](storage-quota/) | Cap each member's namespace so no one fills the disk |

The keys in these files are placeholders: replace them with your own.
