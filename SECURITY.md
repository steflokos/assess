# Security

## Report a problem

Please do not open a public issue for a security problem. Use the private vulnerability reporting of this repository
instead: open the Security tab and choose "Report a vulnerability". Say what you ran, what you expected and what happened. A
small project that shows the problem helps most.

## What counts

assess runs on your machine and reads and writes the files of a project. These are the problems that matter:

- A command writes a file outside the project folder, or reads or writes a project file that is a link to a place outside it.
- A project file, a change set or a rule makes assess run code or read a file it should not.
- The report runs a script that is not its own.
- The private key of a person reaches the server when they sign an iteration in the web interface. It is meant to be read in the browser only,
  and the server is meant to get only the signature and the public key.
- A web page that is not the interface of `assess serve` can read or change a project through it, or the server listens on an
  address that is not on this computer.
- The token of the API of `assess serve` is in an address, or a page that the server serves, such as the report, can read it. The report and the
  diagrams have a token of their own for that reason.
- A change set, a record file or a request makes assess stop, run out of memory or loop, for example with a value that refers to itself.
- A closed iteration can be changed and `assess verify` still says the chain is intact.
- A signature that is not valid passes `assess verify`.

## Versions

Only the latest release gets fixes. assess is a beta (0.x) and the format of a project may change between minor versions.
See "Versions and compatibility" in the README.

## Your keys

assess never stores your private signing key. Keep it somewhere that the project folder cannot reach.
