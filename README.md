<p align="center">
  <img src="assets/assess-logo.svg" alt="assess logo" width="140">
</p>

<h1 align="center">assess</h1>

<p align="center">ISO/SAE 21434 TARA as Code</p>

assess is a command-line tool for threat analysis and risk assessment (TARA) as described in ISO/SAE 21434. You write the
item, its assets, damage scenarios, threat scenarios with attack trees and risks as YAML files and keep them in git.

assess checks the files, calculates feasibility and risk, runs rules that you write yourself and builds a report.

## Target of assess

assess aims to make the TARA process simpler. It does not cover everything that a large TARA tool does, so some features
are missing in these early versions. These are the goals instead:

- **Simplicity.** One binary and plain YAML files. There is nothing to host, no database and no account. The editor
  completes and checks what you write, and `assess serve` opens a web interface on your own computer when you want forms.
- **Speed of work.** `assess generate` writes the repetitive records, so you spend your time on the decisions.
- **Explainability.** ISO/SAE 21434 expects you to justify your decisions. `assess explain` shows how each value was
  calculated and which attack path it chose for a threat scenario.
- **Configurability.** The policy comes with example values. You can change them, and you can write your own rules for what a
  project has to satisfy.

## What assess is, and what it is not

assess supports the ISO/SAE 21434 process. It helps you write down a threat analysis and risk assessment, calculate
with the values you chose, and show how you got each result.

assess does not certify anything. It cannot say that a project meets ISO/SAE 21434, and every report says so. That is a
judgement for people. It depends on how your organisation works and on the evidence you have.

The policy that comes with assess has example values, so that you can start. Before you rely on a result, check the
values against your copy of the standard and the method of your organisation. assess does not include the text of the
standard.

ISO/SAE 21434 is a standard of ISO and SAE International. assess has no connection with either organisation, and
neither endorses it. Their names are only there to say which process the tool supports.

## Getting started

assess is one binary. A project is a folder that you create with `assess init`. It holds your analysis and no code, so
you can keep it in its own git repository. The file `assess.yaml` says which format version the project uses
(`apiVersion: assess/v1beta1`), so you can upgrade the program without touching your files. It also records the version
of assess that wrote the project (`version: v0.1.0`). `assess init` writes it. If you run an older assess than the one
in the file, `assess validate` warns you. `assess version` (or `assess --version`) prints the version that you run.

To build assess from a checkout, run `make build`. The program ends up in `bin/assess` inside the checkout, and
it is not on your PATH. Run `make install` to use it from any folder. This puts `assess` in your Go bin
directory (`GOBIN`, or `$GOPATH/bin`, usually `~/go/bin`). If that directory is not on your PATH, the command
tells you. You can also run assess without building it, for example `go run ./cmd/assess init my-tara`. With Go 1.27.1 or newer,
`go install github.com/steflokos/assess/cmd/assess@latest` installs the latest release.

The folder `examples/ota` is a finished project, with every risk treated and one iteration closed. Read it, or run
the commands below on it. An AI generated it and the data is made up, so it does not describe a real system and is not for production use.

```sh
assess init my-tara              # a clean project: folders and header-only files to fill in
assess validate my-tara          # check the project against the schema
assess schema my-tara            # rewrite schema.yaml after you upgrade assess
assess generate assets my-tara   # an asset record for every element, with all five properties
assess generate threats my-tara  # one threat scenario per asset property that has none
assess eval my-tara              # feasibility and risk of every threat scenario and of the item
assess generate risks my-tara    # write the risk of each threat scenario to concept/risks.yaml
assess explain <threat-id> my-tara   # show how one threat scenario got its numbers
assess diagram my-tara           # the architecture as one SVG image, out/architecture.svg
assess diagram -threat <threat-id> my-tara   # the attack tree of one threat scenario as an SVG image
assess report my-tara            # the whole assessment as one HTML page, out/report.html
assess serve my-tara             # a web interface for the project, on this computer only (see "The web interface")
assess template -o layout.html   # the standard report layout, to start your own from
assess lint my-tara              # check the project against the rules in rules/
assess open my-tara              # what is still open: not calculated, no decision yet, found by a rule
assess delete <kind> <id> my-tara  # delete a record, and with -cascade what depends on it
assess apply changes.json my-tara  # change records from a change set, for programs (see below)
assess finalize my-tara          # close the treatment decisions as an iteration (see "Iterations")
assess sign -key jane.key my-tara   # sign the last iteration with your private key
assess verify my-tara            # check that closed iterations were not changed, and their signatures
assess describe -format json     # how to write the files, for programs
assess export my-tara            # the whole project as one JSON document
```

Exit code `0` means everything is fine. `1` means the project has errors, or warnings when you use `-strict`.
`2` means you used the command wrongly. `-format json` gives the answer as JSON, for programs (see "Using assess
from other programs").

## Order of work

1. Describe the item in `item/`.
2. Run `assess generate assets`. Remove the properties that do not apply. Delete the records of elements that
   are only context.
3. Write the damage scenarios. An asset has a property because losing it leads to a damage scenario.
4. Run `assess generate threats`.
5. Write the attack steps and the controls. Check the values in `policy.yaml`.
6. Run `assess eval` and `assess generate risks`. Then write your treatment decisions.
7. Run `assess lint` and `assess report`.
8. When every risk has its decision, run `assess finalize`. That closes the round (see "Iterations").

`assess generate` writes the assets once and then leaves them alone. Use `-force` to replace the file. For
threat scenarios it only adds the ones that are missing. For risks it only updates the calculated values. It
does not overwrite what you wrote.

## Deleting records

You can delete a record by hand in the file, or let assess do it:

```sh
assess delete <kind> <id> my-tara            # delete one record
assess delete -cascade <kind> <id> my-tara   # also delete what cannot stay without it
assess delete -cascade -dry-run <kind> <id> my-tara   # show the changes and write nothing
```

Other records often use the one you delete. Without `-cascade`, assess does not delete a record that something
still uses. It lists what would have to go and writes nothing.

With `-cascade`, three things happen:

- What is written inside the record goes with it.
- What is made from the id of the record goes. An element has an asset, an asset has threat scenarios and a
  threat scenario has a risk. A record whose required list becomes too short goes too, such as a damage scenario
  that compromises nothing, or a channel that connects fewer than two things. A step in the flow of a function
  goes when one of its lists is left empty.
- The id is taken out of every other place where it is written: the lists of ids, the `and:` and `or:` trees of
  attack steps and controls, and the assets of a damage scenario. An `and:` or `or:` with nothing left is removed.

A cascade does not delete an attack step, a control or an assumption, because other records may use them. They only
lose what pointed at the deleted record. It does not edit `policy.yaml` either. If a control that you delete is
listed under `controls.exclude`, assess names the line and you remove it there.

assess lists every record that it deletes and every record that it changes, each with the reason. Before it writes
anything, it checks the result as a project, as `apply` does. If the result still has errors, nothing is written.
Read the list, or use `-dry-run` or `git diff`, before you keep the result. A step that was deleted from the flow
of a function can leave the steps after it in the wrong place, and `assess lint` and `assess validate` will say so.

## A project folder

```
my-tara/
  assess.yaml         tool configuration: apiVersion, and the optional policy, report template and keys
  project.yaml        project information: name, standards, assessors, date, sources, extra
  policy.yaml         the values that the calculations use: a starting set for you to check and change
  iterations.yaml     the closed iterations (written by assess finalize, not there until the first one)
  schema.yaml         how to structure the files: read this first (generated)
  item/               the item definition: item, functions, components, interfaces, data, channels
  tara/               assets (assets.yaml), damage scenarios, threat scenarios, attack steps, controls
  concept/            risks.yaml: the risk of each threat scenario (written by assess)
  rules/              the rules assess lint checks the project against (written in CEL)
  .assess/ .vscode/   generated editor support
```

`assess init` creates the folders. For each kind that you write by hand, it adds a file with only a header.
These are the architecture, channels, functions, assumptions, damage scenarios, attack steps and controls. It
does not add example records. The files for assets, threat scenarios and risks do not exist yet.
`assess generate` creates them the first time you run it.

`schema.yaml` is your reference. It lists every kind and the folder it goes in. It also says which kinds can
contain which, which attributes are `required` or `optional`, which values are allowed and what a rule can
read. assess writes it from the same declarations that the validator uses, so a file that does not match it
is an error. assess only reads a record from the folder of its kind (subfolders are fine). If a record is in
the wrong folder, the error tells you the right one. A YAML file outside the folders is not read, and you get a
warning.

`project.yaml` has a name, a description, the standards, the assessors and a date. It can also have two lists:

- `sources` lists the documents the assessment is based on. Each one has a `name`. It can also have a
  `location` (a URL, a path or a document number) and the `version` you used.
- `extra` holds blocks of your own. The report shows them in the order you write them. A block has a `title`
  and either a `text` or a table (`columns` and `rows`, with one cell per column).

The report shows both lists in their own section after the cover. No other attributes are allowed in the file,
so a misspelled name is an error. No calculation or rule reads these lists.

## The format

A record starts with a heading that holds its kind and its id, for example `component <id>:`. The attributes
of the record come below it, indented. Indentation also means "contains". A component, for example, can have
interfaces, data and other components written inside it.

The kinds are `item`, `assumption`, `function`, `component`, `interface`, `channel`, `data`, `asset`, `damage`,
`threat`, `step`, `control`, `risk` and `rule`. Every record has a `name`, which is required, and two optional
attributes. `description` says what the thing is and what it does. `notes` is a map of text values for people,
such as an owner, a ticket number or who reviewed it. No report or calculation reads `notes`. A rule can read them
(see "Rules"), so a company can check its own review process.

Here is what else each kind has. `schema.yaml` lists every attribute with its allowed values.

- **item.** You write exactly one per project. `boundary` says what is inside the item, what is outside it and
  which interfaces are external. `environment` says where and how the item is used.
- **assumption.** It has nothing more. Its `name` is the statement itself.
- **function.** It can contain other functions. `flow` is a list of steps. Each step has a `step` text that says
  what happens. It can also have `at`, `data` and `over`.
- **component.** It can contain components, interfaces and data. `functions` lists the functions it realizes,
  but only the ones that no flow names.
- **interface.** You write it inside a component. `exposure` is `External` or `Internal`. `entrypoint` is `true`
  or `false`.
- **channel.** `between` lists the components or interfaces that it connects. You need at least two.
  `entrypoint` works as it does for an interface.
- **data.** It can sit in a component or inside other data. `over` lists the channels it travels over, but only
  the ones that no flow names.
- **asset.** Its id is the id of the element it belongs to. `properties` lists the cybersecurity properties
  that matter for it: Confidentiality, Integrity, Availability, Authenticity or Non Repudiation. You need at
  least one.
- **damage.** `compromises` lists assets and the properties of each that are lost. `impact` rates the damage for
  each stakeholder: `roaduser` (required), `oem` and `supplier`. A stakeholder has four ratings: `safety`,
  `financial`, `operational` and `privacy`. A rating has a `level` (Severe, Major, Moderate or Negligible) and
  an optional `rationale`.
- **threat.** Its id is `<asset>-<stride>`. `damages` lists the damage scenarios it can cause. `steps` is its
  attack path. `assumes` lists the assumptions it relies on.
- **step.** `target` is the element the step is carried out on. `potential` rates the effort in five factors.
  `rationale` says why. `scalability` is Single Vehicle, Limited Batch or Fleet-Wide. `actors` lists who would
  carry it out. `preparedby` says what must happen first. `mitigatedby` lists the controls that mitigate it.
  `assumes` lists the assumptions it relies on.
- **control.** `target` lists where it is deployed. `reduction` rates the effort it demands from the attacker.
  `rationale` says why. `threatenedby` says what can bypass it. `assumes` lists the assumptions it relies on.
- **risk.** Its id is the id of its threat scenario. `type`, `base` and `residual` are calculated by assess.
  You write `treatment`, `rationale` and `reference`. `assumes` lists the assumptions it relies on.
- **rule.** `on` says which kind it checks, `check` is the expression, `severity` is `Error` or `Warning`, and
  `message` is optional. The section on rules explains them.

The architecture says what the item is. Which elements are assets, and for which properties, is a separate
decision. You write that decision in `tara/assets.yaml`. An asset uses the id of its element as its own id. An
element with no asset record is only context. You can rewrite the architecture files without touching these
decisions.

Some rules about the files:

- A component can contain components, interfaces and the data that sits in it. Data can contain data. A
  function can contain functions.
- An id can have letters, digits, `.`, `_` and `-`. Every id must be unique in the whole project.
- An interface can state its `exposure`. `External` means it connects the item to something outside its
  boundary. `Internal` means it connects parts of the item to each other. If you leave it out, the exposure is
  not stated, and assess does not treat it as internal.
- `entrypoint` is separate from `exposure`. It says that an attacker can start an attack there. The report
  lists the external interfaces in the item definition.
- An attribute that points at other records takes one id or a list of ids.
- A function can describe its `flow`. This is a list of ordered steps. Each step says where it happens (`at`),
  which `data` it handles and which channel it goes `over`.
- A flow also gives the direction of a transfer, and you do not write anything extra for it. A step that has
  `over` is at the sender. The next step is at the receiver. Say step 1 is at component A and goes over channel
  X, and step 2 is at component B. Then the data goes from A to B. `assess validate` warns (`flow-channel`) when
  the sender or the receiver is not connected to the channel, or when both are at the same end of it. An
  interface counts as connected through the component it sits in, and the other way round. If a step names
  several channels, it has no single receiver, so assess only checks its sender.
- You write each fact in one place. If a flow already names something, do not repeat it. A component lists
  `functions` only for functions that no flow names. Data lists the channels it travels `over` only when no
  flow covers that transport. If you write both, you get an error that names the line to delete.
- If a value can be worked out from other facts, such as a risk level, it has no attribute. If you write one
  anyway, you get an error.
- Attribute names are always one word.

### Assumptions

An assumption is something the analysis relies on, for example "the owner keeps the phone locked with a password".
You write it once as an `assumption` record in `item/`. Its `name` is the statement. It can also have a `description`.

A threat scenario, attack step, control or risk that only holds while the assumption is true points to it with
`assumes:` (one id or a list). The report lists each assumption together with what relies on it. Rules can
read it as well (`assumption.steps`, `step.assumes` and so on). An assumption is not part of any calculation.
The basic rules warn about an assumption that nothing points to.

### Threat scenarios and attack steps

A threat scenario is written `threat <asset>-<stride>:`. The id is the id of the asset, a hyphen and a STRIDE
word. The word stands for a property. Spoofing is Authenticity, tampering is Integrity, repudiation is Non
Repudiation, disclosure is Confidentiality and denial is Availability. The asset must list that property. This
gives you one threat scenario for each asset property, with nothing repeated.

A threat scenario lists the damage scenarios it can cause and its `steps`. The steps use boolean logic. A step
is an id, or `and:` and `or:` over step ids and more blocks. You can nest them as deep as you need.

You write an attack step once, and any number of threat scenarios can use it. A step rates its effort in five
factors: elapsed time, specialist expertise, knowledge of the item, window of opportunity and equipment. It
can point to other steps with `preparedby`.

`assess generate threats` writes the threat scenarios for you, one for each asset property. It only adds new
ones.

### Controls

You write a control once, like an attack step. It works on the other side, against the attacker.

- `reduction` rates how much effort the control demands from the attacker. It uses the same five factors as
  the `potential` of a step. Lower numbers mean a weaker control.
- `threatenedby` says what can bypass the control.
- `target` says where the control is deployed. It takes one element or a list.

### Relations

The trees in a project come from the relations you write.

- A step lists what must happen before it in `preparedby`. This can be the id of a step or a threat scenario,
  or `and:` and `or:` over ids, nested as needed. The `steps` of a threat scenario work the same way, and their
  leaves can also be threat scenarios.
- A step lists the controls that mitigate it in `mitigatedby` (one id or a list). The attacker has to get past
  every one of them.
- A control lists what can bypass it in `threatenedby`, written like `preparedby`.

assess does not let you write the same thing twice. An `and:` that lists a step which one of its siblings already needs is
an error. A loop is an error. A control that is deployed somewhere other than where the step it mitigates acts
gives a warning.

## Calculation

`assess eval` expands every threat scenario into paths. At each `or` it takes one choice. At each `and` it
takes everything. It also adds whatever each step needs first. A path is a set of steps, so a step that several
branches share counts only once.

Each step has five numbers, which are the policy points of its rating keys. A path combines them factor by
factor in two stages:

1. The steps. `feasibility.combine.steps` says for each factor whether to add the numbers (`sum`) or to take
   the largest (`max`). For example, elapsed time adds up along a series of steps, and expertise takes the
   largest.
2. The controls the attacker has to defeat. `feasibility.combine.controls` says how they are applied on top of
   the steps. A control that is in place raises the other factors by adding.

The five results add up to a total, and the total falls into a feasibility level. The easiest path decides the
feasibility of the threat scenario. This is the **base** result.

The **residual** result also applies the controls. To get past a control, the attacker takes the easier of two
ways. One is the control's `reduction`. The other is a bypass (`threatenedby`). The steps of the bypass
join the path as extra steps and replace the control's reduction. In the worksheet this shows as a line
`bypass <control>`, and its steps are among those listed above it. That is why a residual path can contain
steps that the base path does not.

The risk comes from the matrix cell for the impact of each damage scenario and the feasibility level. assess
looks it up for the base result and for the residual result. It looks it up for every path, not only the
easiest one, and the highest value decides. If two values tie, the easier path wins. Without scalability this
gives the same answer as the easiest path alone, because an easier path is never less feasible. With
scalability it can differ, because the easiest path may reach only one vehicle while a harder path reaches
many. If assess looked only at the easiest path, the risk could fall when an attacker gets a new way in or when
a control is taken away. The highest value over all paths avoids that. The worksheet from `assess explain`
says which path decides each value.

You choose how the impact of a damage scenario is worked out. It happens in two stages. `impact.across`
combines the four categories of one stakeholder. `impact.between` combines the stakeholders. With `max`, the
worst level wins. With `sum`, assess adds the points you give each level (`impact.points`) and looks the total
up in your bands (`impact.levels`).

`scalability.mode` says whether scalability changes the risk:

- `ignored` is the default. assess uses the strict matrix.
- `escalator` raises the matrix value for each scalability, up to a cap. It never lowers a value.
- `matrix` uses a separate risk matrix for each scalability.

`scalability.of` says which step of a path sets its scalability. It can be the narrowest step, the narrowest
entry step or the widest step.

assess does not guess. If a step has no `potential`, if a threat scenario has no `steps`, or if a control has
neither a `reduction` nor a `threatenedby`, the output names the problem and does not calculate that scenario.
It does not treat a missing value as the easiest possible. Without `feasibility.combine` nothing is
calculated, because assess does not pick a rule for you.

`assess explain` prints the working as a table that you can check by hand. It shows the rating key and the
points of every element, the rule for each factor, every stage and the total. For each damage scenario it then
shows the impact stage by stage, and the risk with what scalability added.

The risk of a threat scenario is the highest risk of its damage scenarios. The risk of the item is the highest
risk of its threat scenarios. Each of them is given twice, once with the controls ignored (`base`) and once
with the controls applied (`residual`). So the item has two values. `controls.exclude` in the policy lists
controls that the calculation ignores, as if they were not deployed. It only changes the residual.

### Risks

`concept/risks.yaml` has one `risk` record for each threat scenario. A risk uses the id of its threat scenario
(`risk <threat-id>:`), so a risk and its threat scenario share an id. A risk has:

- the calculated `type` and the two values `base` and `residual`
- your `description`
- your `treatment`: Avoid, Reduce, Share or Accept
- the `rationale` for the treatment
- a `reference`: the id or ids of the risk in an external tool such as Jira or Polarion. It takes one text or a
  list. assess does not read it.

assess creates the last four empty and leaves them alone after that. The report shows the rationale and the
external reference next to the treatment.

The type is a **Goal** when the risk before any control is above `risk.affinity`. That is the highest value the
project accepts without a goal. The type is a **Claim** when the risk is at or below it.

`assess generate risks` adds the records that are missing. It corrects the type and the two values in place and
touches nothing else. `assess eval` warns when the file is out of date, and `-strict` turns that warning into a
failure.

### The policy

The points, levels, rules and matrix are your data. They live in `policy.yaml`, not in the program.
`assess init` writes the file with a starting set of values, so a new project can calculate right away:

- The attack potential points and the feasibility bands come from the example in ISO/SAE 21434, which follows
  ISO/IEC 18045. They come from published sources, not from the standard itself, so check them against your
  copy.
- The risk matrix is an example. The matrix in the standard is only informative, so use the matrix of your own
  method.
- How effort combines along a path, how impact combines and the risk affinity are choices made by assess. The
  standard does not fix them.
- Scalability is not part of the standard. It is left out as a commented section that you can switch on.

All values are whole numbers. The same files always give the same numbers, because assess uses no floating
point and no randomness. When two paths tie, the one you wrote first wins.

## The architecture diagram

`assess diagram` draws the architecture as one SVG image, `out/architecture.svg`. Add `-threat <id>` to draw the
attack tree of one threat scenario instead (see "Attack trees"). Use `-o file` to write it
somewhere else, or `-o -` to print it. `assess report` puts the same picture in the architecture section. The
Go standard library draws it, so you need nothing else. The image has no script in it.

assess draws everything you wrote in `item/`: the components with the components, interfaces and data inside
them, and the channels between them.

- An element that is an asset has a strong outline. An element that is not is greyed out. So the picture shows
  the whole architecture, and it still shows what the analysis is about.
- An interface is orange when it is external, grey when it is internal and white when its exposure is not
  stated. A red dot marks an entry point.
- A channel is a rail with a line down to each of its ends. The rail is thick when the channel is an asset. An
  arrow on a line shows the direction of a transfer that a function flow describes. It points toward the rail
  where the data leaves and toward the element where it arrives. A line with no arrow has no flow through it.
- A line that runs over a component it does not touch is faint and dashed, so a solid line means a
  connection. Where a line crosses a rail, a white gap keeps both easy to read.
- The dashed frame is the item boundary. assess reads it from the interfaces. Take an `External` interface and
  look at what its channel leads to. If that is not the component that owns the interface, it is outside the
  item, and assess draws it above the frame. A component that only connects to things outside is outside as
  well, such as a PKI behind the backend. A component that nothing connects to is drawn inside.

The layout follows fixed rules. The outside sits in a row above. The components of the item sit in rows below.
The channels are drawn as rails between the rows. A small routing step places the rails so that many channels
stay readable:

- A channel goes in the gap between rows that is closest to its ends. Its lines stay short and cross as few
  components as possible. A channel that leads outside the item goes above the item.
- An interface on a top-level component moves to its top or bottom edge, whichever faces its channels.
- The rails in one gap sit on tracks. Rails that do not overlap sideways share a track. assess searches for the
  order with the fewest crossings between a line and a rail.
- The lines that leave one element are placed side by side in the order that keeps them from crossing.
- A channel gets a colour that no neighbouring channel has, from a palette of ten.
- A label goes to the end of its rail where fewer lines run through it.

The diagram reads well up to about 150 elements. A much larger
architecture gets crowded. The label widths are estimates, because the Go standard library has no font
metrics. There is no PNG export, so open the SVG in a browser or convert it with another tool. The function
flows are not drawn, only the direction of their transfers.

## The report

`assess report` writes the assessment as one HTML page, `out/report.html` in the project. Use `-o file` to
write it somewhere else, or `-o -` to print it. The page has its style sheet and one small script inside it,
and it loads nothing from the network. A content security policy in its head allows only that script. So you
can archive the page, mail it or print it. Use the browser's "Save as PDF" if you want a PDF. When you print
it, every part starts on a new page and the navigation is left out.

The script is only a convenience. The page reads the same without it. The script adds:

- a filter box (press `/`). A table row or a derivation worksheet stays when it contains every word you type.
  Everything else is hidden, together with its heading.
- a theme switch for light, dark, or following the system (the default)
- a highlight for the part of the contents you are in, with its sections open
- links that open what they point to, such as a folded worksheet or a row that the filter hides
- a switch for the architecture picture between fitting the page and its actual size


The report follows the order of the work:

- the cover, with the facts of the project and the headline figures. One of them counts the risks at each risk
  level, before any control and with the controls. The others are the goals and claims, the open items and the rules
- the project information: the sources and the extra blocks of `project.yaml`, if there are any
- the item definition: the item, the functions, the architecture and the assumptions. The architecture has the
  diagram, then a table each for components, interfaces, channels and data, and a table that shows what travels
  over each channel and in which direction
- the method and rules in force (the policy). It comes before the analysis, because every value in the analysis
  depends on it
- the threat analysis and risk assessment. It has the assets and their properties, and the damage scenarios
  with the impact rated for each stakeholder and category. It has the threat scenarios with their attack path
  (any of, all of), and the attack steps with a table of their five ratings and points. Then come the attack
  trees (see below). It ends with the attack feasibility, the risk values and the treatment decision for each
  risk
- the cybersecurity goals and claims, with the risk affinity shown above them
- the controls, with the same kind of table for the effort that each one asks from the attacker, and what can
  bypass each one
- the appendices: a traceability table from asset to treatment, the derivation worksheets (the text of
  `assess explain`, unchanged), the open items, the iterations (only when there are any) and the files that were read

The report calculates nothing. Every number comes from the engine. A value that is missing shows as **open**,
not as 0. assess lists every open item and counts them on the cover. An open item can be a threat scenario
without steps, a policy that lacks values, a risk without a treatment decision, a risk that is out of date, or
something the rules found. `-strict` exits with 1 while anything is open.

The page has no clock. The date comes from `project.yaml`. The files that were read are listed at the end, with
the version of assess and a fingerprint, which is a SHA-256 hash over their names and contents. The same files
always give the same page.

The report is material for a review. It does not say that a project complies with the standard. People judge
that from the process of the organisation, and a tool cannot.

### Attack trees

The attack trees part has one block for each threat scenario. It shows the whole structure of the attack. A
step lists what it needs before it, and the controls on it. A control lists what can bypass it, which are
the steps of the bypass. Those steps can need other steps and have controls of their own, so the structure
goes as deep as your records do. A step or a control that comes up again is written in full once. After that it
is marked as seen above.

The steps and controls on the easiest path are marked, before the controls and with them. This is the path that
the calculation chose, so you can see where it goes through the structure.

Each block can be read as text or as a diagram. Choose Tree or Diagram at the top of the block. The diagram is
drawn by assess as an SVG. The threat scenario is on the left, and each column is one more step away from it. A
solid line means that the step needs what it points to. A dashed green line goes to a control. A dotted red line
goes from a control to what can bypass it. A box links to its row when that part is on the page. A line that skips a column
has its own lane, so it does not run behind a box. A tree with more than 250 steps and controls is not drawn,
because the picture would be wider than any screen. The switch needs no script, and a printed page shows the text.

The same outline is used where the calculation names a path. The feasibility table, `assess explain` and its
JSON write each step with its controls under it. For a control they say whether the path defeats it at its
reduction or bypasses it. A control that protects two steps of the path is written in full once, because the
path counts it once.

`assess diagram -threat <id>` writes the diagram of one threat scenario as a file of its own, in
`out/attack-<id>.svg`.

### Your own layout

The report page is built from a template. assess ships a standard template but you can use your own. A
template is an HTML file. You write the HTML you like around placeholders. A placeholder is a name in double
braces, such as `{{cover}}` or `{{section:risk}}`. assess puts that part of the report where the placeholder
is. A part that you do not place is left out of the report.

Start from the standard template. Then name your copy in `assess.yaml`:

```sh
assess template -o report-template.html
```

```yaml
template: report-template.html
```

You can also use a template once, with `assess report -template report-template.html`. The flag wins over
`assess.yaml`. `assess template -list` lists every placeholder. `assess template -list my-tara` also lists the
parts of your report, which `section:<id>` can place.

Some things to know:

- A part brings its sub-parts. `{{section:item}}` places the item definition with its functions, architecture
  and assumptions. Write `{{section:item omit=functions,assumptions}}` to leave some of them out. You can also
  place a sub-part on its own, such as `{{section:components}}`.
- You can leave columns out of the tables of a part with `hide`. `{{section:tara hide=rationale,steps.actors}}`
  leaves out `rationale` from every table in that part that has it, and `actors` only from the tables of the part
  `steps`. The first column of a table holds the ids of the records and stays. The names of the columns are
  the names that the attributes have in the files where there is one, such as `rationale`, `mitigatedby` or
  `entrypoint`. `assess template -list my-tara` shows the columns of every part. A name that no table has is an
  error, and the error lists the columns that exist.
- The numbers follow your template. The first part you place is 1, the next one is 2, and so on.
- You can place a part once. You cannot place it again, or place it inside another part that holds it.
- A link to a part that you left out becomes plain text.
- Your own HTML can go anywhere. You can add a logo (as a `data:` image), a confidentiality line, a signature
  table or a second `<style>` after `{{style}}`. The colours are CSS variables, such as `--accent`.
- `{{csp}}` is the security policy of the page. It blocks scripts of your own and anything from the network.
  If you need them, leave `{{csp}}` out of your template.
- Some texts of the report mention other parts, for example "see the appendix". They stay as they are when you
  leave that part out.
- A note written `{{# like this }}` is for whoever edits the template. It is not written to the page.
- A mistake in the template, such as a name that does not exist, is reported with its line and column. In that
  case assess writes no report. When the template is fine, assess says which parts it left out.
- The template is part of the fingerprint.

## Iterations

You decide how to treat a risk more than once. You decide in a first round, review it, change the design and decide
again. `assess finalize` closes a round. It writes your decisions, as they are now, into `iterations.yaml` and gives
the round a number. Your next changes belong to the next iteration. Nothing is locked, so you can keep editing every
file. The closed rounds stay in `iterations.yaml` as a record.

```sh
assess finalize -note "First review with the supplier" my-tara
assess finalize -dry-run my-tara    # show the iteration and what changed since the last one, write nothing
```

assess closes an iteration only when the project has no errors and nothing is open. Every risk must be calculated, up
to date and have a treatment, and no rule finding may be waiting. If something is open, assess lists it and writes
nothing. It also refuses when the project has no risk, and when nothing has changed since the last iteration.

An iteration records:

- its number, and the date and time you finalized it. assess uses the current time, unless you give one with `-date`.
  Write it as RFC 3339 with the time zone, for example `2026-10-20T09:30:00Z` or `2026-10-20T11:30:00+02:00`
- who finalized it. Give each person with `-by`, or assess takes the assessors from `project.yaml`
- your `note` (`-note`) and the version of assess
- a fingerprint of the project files the decisions were made from
- your decision for every risk: the treatment, the base and residual values, and a short code for the rationale and
  the reference. assess does not copy the text. If you change your reasoning, the code changes, and `git diff` shows
  you the words
- the hash of the iteration before it, and its own hash

`assess finalize` also tells you what changed since the last iteration: which risks were added or removed, and which
have another treatment, other values or other reasoning. The Iterations part of the report shows the same.

### The hash chain

assess hashes the content of an iteration with SHA-256. It writes the content in a fixed form first, so spaces and the
order of lines in the file do not change the hash. The form is `Canonical` in `internal/model/iteration.go`, if you
want to compute a hash yourself. Each iteration also holds the hash of the one before it. Change anything in a closed
iteration and its hash no longer matches. Change the hash too, and the next iteration no longer points at it. Either
way the chain breaks where you made the change.

```sh
assess verify my-tara
assess verify -head sha256:8332260a8904... my-tara
```

`assess verify` checks the numbers, the links and the hashes, and names the first iteration that is wrong. It is not
part of `assess validate`. Validate looks for mistakes in your records, and verify looks for changes to what you
closed. It works even when the records have errors.

The chain has limits that you should know:

- You can edit the file, so it cannot be made unchangeable. Someone could delete the newest iterations, or write the
  whole file again with new hashes, and the chain would still look right. Only a copy of the last hash, kept
  somewhere else, shows this. `assess finalize` prints the hash. Keep it outside the project, for example in a signed
  git tag, in the ticket or in the mail to the reviewer, and compare it with `-head`.
- Verify tells you that something changed after it was closed. It does not tell you whether the decisions were right.

### Signatures

A signature shows who stands behind a hash. Signing is optional. The private key stays with you. assess reads the key
file only while it signs, and it does not store the key or print it. The project keeps the signature and the
fingerprint of the public key, and nothing else.

```sh
assess sign -key ~/keys/jane.key my-tara              # the last iteration
assess sign -key ~/keys/jane.key -iteration 1 -by "Jane Doe" my-tara
assess verify -keys keys/ my-tara                     # a public key, or a folder of .pub and .pem files
```

The key must be an ed25519 key. The private key is a PEM file in PKCS#8 form without a passphrase, and the public key
is a PEM file in PKIX form. These two commands make a pair:

```sh
openssl genpkey -algorithm ed25519 -out jane.key
openssl pkey -in jane.key -pubout -out jane.pub
```

You can say once where the public keys are, with `keys: keys` in `assess.yaml`. The path is relative to the project,
and `-keys` wins over it. A signature that has no key to check it shows as *not checked*. That does not fail
`assess verify`, unless you use `-strict`. The signature covers the hash, so it also covers every iteration before it.
Several people can sign the same iteration, each with their own key. The same key signs an iteration only once.

assess does not yet read keys with a passphrase, sign with a hardware key or an agent, or fetch public keys from a
web address.

## Rules

`rules/` holds the rules that `assess lint` checks the project against. A rule is a record with:

- `on`: the kind of record it checks (item, assumption, function, component, interface, channel, data, asset,
  damage, threat, step, control or risk)
- `check`: a CEL expression that is true when the record passes
- `severity`: `Error` makes `assess lint` fail. `Warning` only makes it fail with `-strict`.
- `message`: an optional text that says what is wrong

```yaml
rule goal-is-treated:
  name: A goal is avoided or reduced
  on: risk
  severity: Error
  check: risk.type != 'Goal' || risk.treatment in ['Avoid', 'Reduce']
  message: a goal must be avoided or reduced
```

`assess init` writes five basic rules to `rules/basic.yaml`. They follow from what the records mean:

- an accepted risk is within the risk affinity
- a risk treated by reducing is reduced
- every property of an asset is in a damage scenario
- a control mitigates a step
- an assumption is relied on

The file explains each one. You can change it, extend it or shorten it.

Rules about your own process are up to you. Here are some example checks:

- every risk has a treatment decision: `risk.treatment != ''`
- a goal is met when what is left after the controls is within the risk affinity:
  `risk.type != 'Goal' || risk.residual <= policy.affinity`
- a major or severe rating says why:
  `damage.ratings.all(r, r.level in ['Negligible', 'Moderate'] || r.rationale != '')`
- a rated attack step or control says why: `step.rationale != '' || !step.rated`
- an accepted or shared risk says why: `!(risk.treatment in ['Accept', 'Share']) || risk.rationale != ''`

The record being checked is a variable named after its kind: `risk`, `threat`, `step`, `control`, `damage`,
`asset`, `assumption`, `function`, `component`, `interface`, `channel`, `data` or `item`. Every rule can also use
`policy` and the lists `assumptions`, `functions`, `components`, `interfaces`, `channels`, `dataelements`,
`assets`, `damages`, `threats`, `steps`, `controls` and `risks`. `schema.yaml` lists all the fields. If you make
a typo, assess finds it when it validates the project, and the message gives the column in the expression.

Every record has a `notes` field in a rule: a map of text. A note that is not written is not there, so ask
with `has()` before you read it. This lets you write a review gate of your own. A tool or an agent that writes
records can tag them with `notes: {source: some-tool}`. This rule then asks for a person to review them:

```yaml
rule component-reviewed:
  name: A component that came from a tool has been reviewed
  on: component
  severity: Warning
  check: "!has(component.notes.source) || has(component.notes.reviewed)"
  message: came from a tool, and nobody has reviewed it yet (add notes.reviewed)
```

The same works for every other kind. Findings of a rule show up in `assess lint` and in the open items of the
report, and `-strict` fails while any is left.

A `message` can name a field of the record in braces, such as `{unjustified}`. That field holds the properties
of an asset that no damage scenario compromises. The finding shows its value. If a rule only repeats something
the report already lists as open, such as "every risk has a treatment", the same gap shows up twice.

A rule can only say whether a record passes. The calculation stays in the engine. assess reports a failing
record at its own `file:line:col`, with the id of the rule as its code.

A value that is still open (not calculated, or not set in the policy) has no value. A rule that needs such a
value is reported as *could not be checked*. assess does not count it as passed, and not as 0. `has(risk.residual)`
asks whether a value is there. So `!has(risk.residual) || risk.residual < risk.base` gets an answer in both
cases. A rule stops when it reaches a cost limit. The same project always gives the same findings in the same
order.

## Using assess from other programs

Other programs can use assess: a script, a step of a pipeline, an MCP server or an AI agent. They talk to assess by
running commands and reading JSON. They need nothing but the `assess` program.

### JSON from the commands

Add `-format json` to `validate`, `lint`, `eval`, `explain`, `generate`, `open`, `describe`, `apply`, `delete`, `finalize`,
`sign`, `verify`, `template -list` or `version`. `export` always gives JSON. Standard output then holds exactly one JSON document, always with the same
shape:

```json
{
  "assess": {"version": "v0.1.0", "apiVersion": "assess/v1beta1"},
  "command": "eval",
  "ok": true,
  "diagnostics": [],
  "result": {}
}
```

- `ok` is true when the command exited with 0.
- `diagnostics` is a list of errors and warnings. Each one has a `severity`, a `code`, a `file`, a `line`, a
  `column` and a `message`. It is a list even when it is empty. It is filled when the project has errors too, so a
  program never has to read text.
- `result` is what the command found. It is left out when there is nothing to say.

In this mode the human text of a command goes to stderr. The exit code is `0` when all is well, `1` when the project
has findings (errors, or warnings under `-strict`) and `2` when the command line is wrong or something failed.

### Reading a project

- `assess describe -format json` says how to write the files: every kind of record, where it goes, what it can
  contain, how its id is written, and every attribute with its type, whether it is required and its allowed values.
  It also says what a rule can read. A program builds its calls from this, and it only needs to read it once. It
  says the same as `schema.yaml`.
- `assess export` gives the whole project as one document: every record as it is written (with its file and line),
  the plain files, the closed iterations, the transfers of the function flows, what assess calculated, and what is open. With `-derived` it
  adds what is worked out about each record, the same views that rules read. It works on a project with errors too.
  The diagnostics are in the document, the results are left out and the exit code is `1`.
- `assess open -format json` lists everything that is still open. It is the same list as the open items of the
  report. Each item has a `code`, so a program can tell what to do: `no-item`, `policy-gap`, `not-calculated`,
  `risk-not-calculated`, `damage-uncaused`, `no-risks`, `risk-missing`, `risk-stale`, `no-treatment`,
  `rule-finding` or `rule-not-checked`. It also names the record (`kind` and `id`). `-strict` exits with `1`
  while anything is open. A program that fills in a project runs `open` again and again until the list is empty.
- `assess explain -format json <threat-id>` gives the worksheet of one threat scenario as data. It also has an `outline` of
  the easiest paths, which puts each control under the step it protects (see "Attack trees").

### Writing records

A program should not write YAML by hand. The format has small traps that can break the project. `assess apply`
writes the records for it. It takes a change set, in JSON or in YAML:

```json
{
  "apiVersion": "assess/v1beta1",
  "changes": [
    {"op": "put", "kind": "component", "id": "unit-1",
     "attributes": {"name": "First unit", "notes": {"ticket": "ARCH-101"}}},
    {"op": "put", "kind": "interface", "id": "unit-1-port", "parent": "unit-1",
     "attributes": {"name": "Service port", "exposure": "External", "entrypoint": true}},
    {"op": "delete", "kind": "step", "id": "old-step"}
  ]
}
```

- `put` creates the record. If the record exists, it sets the attributes that you name and leaves the others alone.
  A `null` removes an attribute. If everything is already as asked, nothing changes, so the same change set can be
  sent again and again.
- The attributes have the names and the values that they have in the files. `describe` lists them.
- A record that is written inside another one says which with `parent`. A new record goes in the usual file of its
  kind, for example `item/architecture.yaml`, or in the `file` that you name.
- `delete` removes a record and what is written inside it. A record that is not there is already gone. If something
  still refers to what you delete, the change set is refused, and `blocked` lists the records. Either delete those
  records in the same change set, or add `"cascade": true` to the delete. It then does what `assess delete -cascade`
  does (see "Deleting records"), and the result lists each record that it deleted or changed, with a `reason`.
- `-source name` adds `notes: {source: name}` to every record that the change set creates or changes. Rules can
  read it (see "Rules"), so a company can ask for a review of everything that came from a tool.
- `-dry-run` shows what would change, as a diff, and writes nothing.
- In JSON, the result has `effects` when the change moves a result of the calculation. Each entry names a threat scenario, or the
  item, with its risk values and feasibility levels before and after. A threat scenario that the change creates or removes has only
  one of the two. It is left out when nothing moves, and when the project cannot be calculated.

Before assess writes anything, it checks the result as a project, in a copy. If the result has errors, nothing is
written. The errors say which file, line and column they are at in the files as they would be. When an error is
caused by a record that still refers to something you deleted, the result lists that record under `blocked`. The
files are edited as text: only the lines that change are different, and the comments, the blank lines and the
way the author wrote everything else stay as they are.

`assess apply` does not run the rules. A record that a rule flags is not an error, and it is not meant to be.
`assess lint` and `assess open` list those.

### One run, from start to end

1. `assess describe -format json`, once.
2. `assess apply` with the architecture, then a person looks at the diff or the git branch.
3. `assess generate assets`, then `apply` to remove what is only context.
4. `apply` the damage scenarios, then `assess generate threats`.
5. `apply` the attack steps and controls, with their ratings and a rationale.
6. `assess open -format json` until nothing is left. Fix what it lists, with `apply` and `generate risks`.
7. A person decides the treatment of each risk. It can be written with `apply` too.
8. `assess lint -strict` and `assess report -strict`.
9. `assess finalize` to close the round. It refuses while anything is open, and `-format json` lists what.

Every command that writes does it in one piece, so an editor never sees half a file. The commands that change the
records (`apply`, `delete`, `generate`, `finalize` and `sign`) also lock the project while they work. Two of them at the same time take
turns, so no change is lost. A command that only reads waits until a change is finished, so it never sees one
half done. A command waits up to 30 seconds for the lock and then stops with an error. The lock is gone when the
command ends, even if the command was killed. The same files always give the same output, so a run can be repeated
and compared.

## Editor support

`assess init` writes the editor files, and so does `assess schema` in an existing project. They are:

- `.assess/schema.json` for the record files
- `.assess/schema-assess.json`, `.assess/schema-project.json` and `.assess/schema-policy.json`, one for each
  file at the root
- `.assess/ids.json`, which holds the ids of your records (see below)
- `.vscode/settings.json`, `.vscode/extensions.json` and `.vscode/tasks.json`, if they do not exist yet

Commit them. Nothing depends on them, and `assess validate` is still the final check. After you upgrade assess,
`assess validate` warns (`stale-schema`) when `schema.yaml` or one of the schema files differs from what the
installed assess would write. Run `assess schema` to update them. assess does not report `ids.json` as stale, because it
follows your files.

Every file that assess writes starts with a line like
`# yaml-language-server: $schema=../.assess/schema.json`. Any editor that runs the YAML language server finds
the schema from that line, so you need no editor setting.

Type the word of a kind (`component`, `damage`, `step` and so on) to get a snippet for the whole record. The
snippet has the attributes that the schema requires, plus what a record needs to count: the `damages` and
`steps` of a threat, the `potential` and `scalability` of a step, the `reduction` of a control and the
`treatment` of a risk. Each text is an empty stop, and each value is a choice list. The other attributes
(`notes`, `assumes`, `rationale`, `reference` and so on) come from completion when you want them.

### Ids

Where a record refers to another one, the editor offers the ids that fit, each with the name of its record:

- `between` of a channel and `at` of a flow step: components and interfaces
- `data` and `over` of a flow step: data and channels
- `functions` of a component: functions
- the keys of `compromises`: assets, and then only the properties that asset lists
- `damages` of a threat scenario: damage scenarios
- `steps` of a threat scenario, `preparedby` of an attack step and `threatenedby` of a control: attack steps
  and threat scenarios
- `mitigatedby` of an attack step and `exclude` in `policy.yaml`: controls
- `target` of an attack step or a control: components, interfaces, channels and data
- `assumes`: assumptions

Type the first letters of the id. The editor does not open the list by itself on an empty spot. You can open it
with the key for Trigger Suggest (Ctrl+Space by default). The list only gives suggestions. The editor accepts
any other value, and `assess validate` tells you which ids do not exist.

The ids come from `.assess/ids.json`. Every assess command that reads the project rewrites the file when the
ids have changed. `assess schema -watch` rewrites it each time you save a file. In VS Code, the task in
`.vscode/tasks.json` starts it when you open the folder. VS Code asks once if automatic tasks may run, and
`assess` must be on your PATH. In another editor, run `assess schema -watch` in a terminal.

### Editors

- **VS Code** (or Cursor, VSCodium): install the recommended YAML extension (`redhat.vscode-yaml`). It gives
  you keys, valid values, ids and hover descriptions.
- **Neovim, Helix, Zed, Emacs**: install `yaml-language-server`. The first line of each file points it at the
  schema, so there is nothing else to set.
- **JetBrains IDEs**: go to Settings, Languages & Frameworks, Schemas and DTDs, JSON Schema Mappings. Add
  `.assess/schema.json` (draft 7). I have not tried the ids there.

assess does not rewrite existing editor settings. If your `.vscode/settings.json` or `.vscode/tasks.json` already
exists, assess prints what you need to add.

## The web interface

`assess serve` shows a project in your web browser. It is for the moments when you would rather fill in a form than write YAML.
The files stay the only source of truth. You can edit them in your editor while the page is open, and the page shows the change
within a few seconds.

```sh
assess serve my-tara
```

assess prints an address that ends in `#t=` and a token. Open the whole address. The token is new on every run. Without it, the
page cannot read or write anything. `-addr 127.0.0.1:9000` picks another port.

What you can do in the page:

- **Follow the path.** The overview shows the seven steps of "Order of work" and says which one is next, with a button for it. A new
  project starts there. A finished one shows its status.
- **Find anything.** Press Ctrl K (Cmd K on a Mac), or `/`, and type part of a name or an id.
- **Change a record in a form.** The form is built from the description of the format, so it offers the allowed values and the ids that
  exist. It shows the fields that are required or have a value, and the others are one click away in "Add a field". An id is a chip that
  opens its record. The attack path of a threat scenario is edited as groups of "all of" and "any one of". A rating is a row of
  selects with the points that the policy gives. The impact of a damage scenario is a grid of stakeholders by categories.
- **See what a change does before you save it.** Every change is checked first. The errors show where they are in the files, the lines
  that would change are shown as a diff, and the page says which threat scenarios would get a different risk. Save writes only those
  lines, Ctrl S does the same, and Undo puts the old values back.
- **Decide the risks in one table.** The decisions page lists every risk with its treatment, and the changes are checked and saved
  together.
- **See what a record is connected to.** The side of a record page shows its calculation, its attack tree, what it uses and what uses it.
- **Delete a record.** The page says what depends on it before anything is removed.
- Let assess write assets, threat scenarios and risks, and close an iteration.
- See the calculation, the worksheet of each threat scenario, the report and the diagrams.

What the page does not do: it shows `assess.yaml`, `project.yaml` and `policy.yaml` but does not edit them, it does not create a
project (run `assess init`), and it does not sign. Your private key stays on the command line, where `assess sign` reads it.

The page has no login, so `assess serve` listens on this computer only and refuses any other address. A web page that is open in
the same browser cannot use it, because every request has to carry the token. The page runs the same commands as the command line,
so what it writes passes the same checks as `assess apply`.

## Versions and compatibility

assess uses semantic versioning. While the first number is 0, assess is a beta. A new minor version, such as 0.2.0, can
change what a command prints, its options or the format of a project. A patch version, such as 0.1.1, fixes mistakes
and breaks nothing that worked. `CHANGELOG.md` lists what changed in each version and what you have to do about it.

From 1.0.0 on, a change that breaks a project, a command or the JSON of a command needs a new major version. The
format `assess/v1beta1` becomes `assess/v1` then.

Three things have a version of their own:

- The program. `assess version` prints it, and `assess.yaml` records which version wrote the project. assess warns you
  when a project comes from a newer version than the one you run.
- The format of a project. This is `apiVersion` in `assess.yaml`, and the JSON of every command carries the same value.
  This version reads `assess/v1beta1` only.
- The text that an iteration hash is made from, called `assess-iteration-v1`. It does not change without a new name. So
  an iteration that one version finalized is one that the next version can verify.

The tests guard the format in two ways. `examples/ota` is checked on every change, and its numbers, its lint result and
the shape of its report must stay the same. And `internal/schema/testdata/format.baseline` lists every kind, attribute,
value and rule field. A change that removes or alters one of them fails the tests. If you mean to make that change,
say so in `CHANGELOG.md`.

## Development

[`CONTRIBUTING.md`](CONTRIBUTING.md) says how to build assess, run the tests and send a change. To report a security
problem, read [`SECURITY.md`](SECURITY.md).

## License

assess is open source under the [Apache License 2.0](LICENSE). Stefanos Flokos holds the copyright. You can use assess at
work, change it and build it into your own products. The projects and reports you make with it belong to you.

The license gives no rights to the name assess or to its logo. Code you contribute comes under the same license (section 5
of the Apache License).

[`NOTICE`](NOTICE) names the copyright holder. [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) lists the libraries that assess
uses, with their licenses.
