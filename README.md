# Zutfen Charter

Charter is an early-stage, model-independent AI workspace designed to let organizations govern which models their teams use, where data can go, and what work must be preserved.

## Status

**Design and pilot setup only.** There is no supported runtime, deployment, or compliance claim yet. Use synthetic data only. Do not put customer records, secrets, evidence bundles, or real case details in this public repository or its issues.

## First milestone: governance before the client

Prove that a single control plane can enforce project boundaries and model policy, preserve the actual AI work performed under a matter hold, and export independently verifiable evidence. The first slice uses a minimal web client or test harness, two synthetic projects, and test model endpoints. Desktop packaging and ZCode adoption are separate decisions, not pilot dependencies.

- [Pilot backlog](https://github.com/Zutfen-LLC/charter/issues)
- [Pilot design and acceptance](docs/pilot.md)
- [Working in this repository](CONTRIBUTING.md)
- [Governance and evidence contracts (ADR 0001)](docs/adr/0001-governance-and-evidence-contracts.md), with [role matrix](docs/contracts/role-matrix.md), [state transitions](docs/contracts/state-machines.md) and [versioning](docs/contracts/versioning.md)

Check the contract fixtures (Python 3 standard library only):

```bash
python3 -m unittest discover -s tests/contracts -v
```
