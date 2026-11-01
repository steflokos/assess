# Changelog

assess uses semantic versioning.

## Unreleased

Changes to how assess is used. The format of a project and the JSON of the commands stay the same.

- A flag can go anywhere on the command line, so `assess explain <threat-id> -all` works. After `--` every word is an argument. A flag
  after the folder used to be refused.
- A command that is given no folder finds the project in the nearest folder above that has an `assess.yaml`, the way git finds its
  repository, and says which folder it took. `init` and `serve` still only look at the folder they are given.
- `explain`, `delete` and `diagram -threat` name the id that was meant when the one given does not exist. A value of a fixed list that
  differs from an allowed one only in case, spaces, hyphens or underscores, such as `major` for `Major`, is named in the error.
- Each line of `assess open` starts with the `file:line:col` of its record, as a diagnostic does.
- In text, `apply` and `delete` end with what the change moves in the calculation, also in a dry run. JSON had this as `effects` already.
- On a terminal, an error is written in bold red and a warning in yellow. `NO_COLOR`, pipes and files get the plain text as before.
- `serve -open` opens the page in the browser. When the port is taken, `serve` says so and how to get a free one.
- In the web interface: a project with errors points at them, and not at a step that waits for the calculation. The calculation, open
  items and decisions pages list the errors. The calculation and decisions tables sort by any column, the highest risk first, and filter
  by goals or claims. The count of undecided risks follows the choices on the page.

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
- `assess serve`, a web interface on your own computer. It guides you along the steps, searches, edits records in forms, shows what a
  change does to the risk before you save it, and decides the risks in one table.
- `apply` says in JSON what a change does to the calculation (`effects`). A change can say what it read (`was`, `new`), and assess refuses
  to overwrite what someone else changed since. `apply` also writes the plain files, `assess.yaml`, `project.yaml` and the policy, as a whole.
- `assess sign` takes a signature that was made elsewhere (`-signature` with `-public`), so that a key never has to reach assess.
- In the web interface: edit the settings, sign in the browser, a warning when someone else changed what you are editing, and create a
  project in an empty folder.
- A project is checked more than once before it is written: a change set cannot hold anchors or aliases, a file with more than one YAML
  document or a line separator that an editor does not show is not edited, a file or a folder of the project that is a link out of it is not
  read or written, and the report and the diagrams have a token of their own. When one value of a block changes, the rest of the block is
  written as it was.
- `assess help <command>` says how a command is written. A typo
  in the name of a command is met with the one that was meant. `verify` shows the start of each key and flags a key that signs twice.
- Scalability raises the impact of a damage scenario, per path, and not the risk value. `scalability.shift` in the policy gives the levels for a
  limited batch and for the whole fleet. A hard attack stays small however far it reaches, and a control still lowers the risk. A policy that
  has the keys of the escalator (`mode`, `of`, `raise`, `cap`, `matrix`) is refused, and the message says what to write now. In the JSON of
  `eval` and `explain`, a risk has `impact` (as rated, for one vehicle), `scalability`, `shift` and `raised` (the impact after the shift), and not
  `cell`, `raise` and `cap`, and `rules.risk.scalability` is `ignored` or `shift`. The policy refuses a number that is not whole and a section
  that is written with nothing in it.
- A change that reaches several files is written as a whole. All the files are written to temporary files first, and the files are swapped in
  only then. When a swap fails, the ones that were swapped are put back. This holds for `apply` and `generate risks`.
- In the web interface: an attack step is made from the picker of an attack path, and is saved, checked and undone together with the record.
  After a save, the page lists the open items that the change made.
- A list that is written one item to a line stays so when an item is taken out or put in. Undo gives the file back as it was.
- `examples/ota`, a finished example project.

Known limits of this beta:

- The numbers in the policy that comes with assess are examples. Check them before you rely on a result.
- Signing keys must be ed25519 keys in PKCS#8 form, without a passphrase.
- The tests run on Linux, macOS and Windows in CI. Where there is no `flock`, as on Windows, assess locks a project with a lock
  file instead, and readers do not wait for a change to finish. A command that was killed leaves the lock file behind for five minutes.
- This is a beta, so expect some bugs. Later versions fix them and add features.
