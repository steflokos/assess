# Changelog

assess uses semantic versioning.

## 0.1.0

The first beta. Projects use the format `assess/v1beta1`.

What is in it:

- Projects written as YAML files: the item, assets, damage scenarios, threat scenarios with attack steps and controls,
  and risks with their treatment. `assess init` makes a project, and `assess generate` writes the repetitive records.
- Calculation of attack feasibility, impact and risk from a policy that you can change. `assess explain` shows every
  step of a result.
- Rules in CEL that `assess lint` checks, with a basic set that comes with a new project.
- A report as one HTML page, with attack trees and a page template that you can change.
- Iterations. `assess finalize` closes the treatment decisions in a hash chain, `assess verify` finds a change to it,
  and `assess sign` adds your signature.
- Commands for programs: `-format json`, `apply`, `delete`, `export`, `describe` and `open`.
- `examples/ota`, a finished example project.

Known limits of this beta:

- The numbers in the policy that comes with assess are examples. Check them before you rely on a result.
- Signing keys must be ed25519 keys in PKCS#8 form, without a passphrase.
- The tests have only run on macOS so far. Where there is no `flock`, as on Windows, assess locks a project with a lock
  file instead. That code is written but not yet tested on Windows.
- This is a beta, so expect some bugs. Later versions fix them and add features.
