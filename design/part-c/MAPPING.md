# Part C mapping

The `design/part-c/C1` through `C7` folders preserve the design-only contracts
folded by pull request #63. Their folder numbers are scaffold identifiers, not
one-to-one implementations of the Paper MASTER-PLAN Part C letters.

| MASTER-PLAN item | Work item | Related #63 scaffold contract | Reconciliation |
|---|---|---|---|
| C1 | Close the check-open race with open-by-fd in the host. | `C1` fail-closed; `C4` call-bound receipt; `C7` cross-roof dependency. | The implementation crosses the gate and host boundary. The `C1/` folder alone does not define or satisfy it. |
| C2 | Close the host S3 findings. | `C2` closed schema and log-before-act; `C3` authority transition; `C7` cross-roof dependency. | Host findings may use several scaffold contracts. They remain separate until each named S3 has a failing test and destination receipt. |
| C3 | Exercise the kill switch on the live hook path. | `C1` fail-closed; `C3` authority transition. | The existing gate-level kill-switch evidence is not the MASTER-PLAN live-path result. |
| C4 | Close K3 through K8. | Depends on the contract each K-item tests. | K3-K8 are a work queue, not aliases for scaffold folders `C3`-`C8`. Map each item to its actual boundary before implementation. |
| C5 | Prove Windows grant ownership and ACL behavior. | `C1` fail-closed; `C2` closed schema and log-before-act. | This is host-specific evidence. The #63 scaffolds contain no Windows ACL measurement. |
| C6 | Mint the Zenodo DOI only with B7. | No scaffold implements release authority. | `C6/` is the four-plane threat-model contract. MASTER-PLAN C6 is a held publication action and remains coupled to B7. |
| C7 | Close Forseti follow-ups. | Any of `C1`-`C7`, according to the finding. | Forseti findings route to the boundary they falsify. `C7/` only defines cross-roof object and dependency handling. |

## State boundary

Pull request #63 folded pre-code contracts. It did not implement MASTER-PLAN
C1-C7, change the gate decision path, or measure runtime behavior. Judge apply
remains false. B7 and the Zenodo DOI remain held.
